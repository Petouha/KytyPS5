#include "log_analyzer/analyzer.h"
#include "log_analyzer/parser.h"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <sstream>
#include <string>

namespace {

using LogAnalyzer::Analyze;
using LogAnalyzer::ErrorSignature;
using LogAnalyzer::Event;
using LogAnalyzer::FatalCrash;
using LogAnalyzer::FatalCrashSignature;
using LogAnalyzer::Finding;
using LogAnalyzer::FormatJson;
using LogAnalyzer::FormatOptions;
using LogAnalyzer::FormatSummary;
using LogAnalyzer::LogEvent;
using LogAnalyzer::Parse;
using LogAnalyzer::UnresolvedImport;

std::vector<LogEvent> ParseText(const std::string& text) {
	std::istringstream input(text);
	return Parse(input);
}

TEST(LogAnalyzerParser, ParsesFullUnresolvedImport) {
	const auto events = ParseText(
	    "Unresolved import stub called [0]: patch_vaddr=0x00000009026c4eb0 jmprela_index=449 "
	    "symbol=Y295ygEccqk[NpCppWebApi_v1][NpCppWebApi_v1.1][Func] type=Func bind=Global "
	    "program=eboot.bin\n");

	ASSERT_EQ(events.size(), 1u);
	EXPECT_EQ(events[0].line_number, 1u);
	const auto* import = std::get_if<UnresolvedImport>(&events[0].event);
	ASSERT_NE(import, nullptr);
	EXPECT_EQ(import->symbol, "Y295ygEccqk[NpCppWebApi_v1][NpCppWebApi_v1.1][Func]");
	EXPECT_EQ(import->program, "eboot.bin");
	EXPECT_EQ(import->import_type, "Func");
	EXPECT_EQ(import->import_bind, "Global");
	EXPECT_FALSE(import->is_bad_record);
}

TEST(LogAnalyzerParser, ParsesBadRecordUnresolvedImport) {
	const auto events =
	    ParseText("Unresolved import stub called [3]: record_id=7 symbol=<bad-record>\n");

	ASSERT_EQ(events.size(), 1u);
	const auto* import = std::get_if<UnresolvedImport>(&events[0].event);
	ASSERT_NE(import, nullptr);
	EXPECT_TRUE(import->is_bad_record);
}

// The console-only printf() twin of the line above; Phase 1 reads _kyty.txt
// itself, not a terminal paste, so this shape is not recognized.
TEST(LogAnalyzerParser, IgnoresConsoleOnlyImportLine) {
	const auto events = ParseText("Unresolved import stub called: SomeSymbol[Lib][Lib.1][Func]\n");

	EXPECT_TRUE(events.empty());
}

TEST(LogAnalyzerParser, ParsesFatalCrashOnSingleLine) {
	const auto events = ParseText("--- Build ---\n"
	                              "Official build KytyPS5-2026-11-11-bc934ef\n"
	                              "--- Fatal Error ---\n"
	                              "Not implemented (!m_graphics.mesh_shader_enabled) in "
	                              "D:\\a\\KytyPS5\\KytyPS5\\src\\graphics\\host_"
	                              "gpu\\renderer\\pipeline\\pipelineCache.cpp:604\n");

	ASSERT_EQ(events.size(), 1u);
	const auto* crash = std::get_if<FatalCrash>(&events[0].event);
	ASSERT_NE(crash, nullptr);
	EXPECT_EQ(crash->title, "FatalError");
	EXPECT_EQ(crash->build_label, "Official build KytyPS5-2026-11-11-bc934ef");
	EXPECT_EQ(crash->message, "Not implemented (!m_graphics.mesh_shader_enabled)");
	EXPECT_EQ(crash->source_file, "src/graphics/host_gpu/renderer/pipeline/pipelineCache.cpp");
	EXPECT_EQ(crash->source_line, 604u);
}

// A few EXIT() call sites embed their own '\n', pushing " in <file>:<line>"
// onto its own line instead of staying on the message's line.
TEST(LogAnalyzerParser, ParsesFatalCrashSplitAcrossTwoLines) {
	const auto events =
	    ParseText("--- Build ---\n"
		          "Official build KytyPS5-2026-11-11-bc934ef\n"
		          "--- Error ---\n"
		          "unsupported texture mip view changes physical layout: base=6 last=6 max=5 "
		          "extent=1920x1080x1 tile=27\n"
		          " in "
		          "D:\\a\\KytyPS5\\KytyPS5\\src\\graphics\\host_"
		          "gpu\\renderer\\pipeline\\descriptors.cpp:607\n");

	ASSERT_EQ(events.size(), 1u);
	const auto* crash = std::get_if<FatalCrash>(&events[0].event);
	ASSERT_NE(crash, nullptr);
	EXPECT_EQ(crash->title, "Error");
	EXPECT_EQ(crash->message,
	          "unsupported texture mip view changes physical layout: base=6 last=6 max=5 "
	          "extent=1920x1080x1 tile=27");
	EXPECT_EQ(crash->source_file, "src/graphics/host_gpu/renderer/pipeline/descriptors.cpp");
	EXPECT_EQ(crash->source_line, 607u);
}

TEST(LogAnalyzerParser, HandlesCrlfLineEndings) {
	const auto events = ParseText("--- Build ---\r\n"
	                              "Official build KytyPS5-2026-11-11-bc934ef\r\n"
	                              "--- Fatal Error ---\r\n"
	                              "Not implemented (x) in src/foo.cpp:10\r\n");

	ASSERT_EQ(events.size(), 1u);
	const auto* crash = std::get_if<FatalCrash>(&events[0].event);
	ASSERT_NE(crash, nullptr);
	EXPECT_EQ(crash->source_file, "src/foo.cpp");
	EXPECT_EQ(crash->source_line, 10u);
}

TEST(LogAnalyzerParser, NormalizesWindowsAndLinuxPathsToSameSourceFile) {
	const auto windows_events =
	    ParseText("--- Build ---\n"
		          "Official build X\n"
		          "--- Error ---\n"
		          "boom in D:\\a\\KytyPS5\\KytyPS5\\src\\loader\\runtimeLinker.cpp:720\n");
	const auto linux_events =
	    ParseText("--- Build ---\n"
		          "Official build X\n"
		          "--- Error ---\n"
		          "boom in /home/runner/work/KytyPS5/KytyPS5/src/loader/runtimeLinker.cpp:720\n");

	ASSERT_EQ(windows_events.size(), 1u);
	ASSERT_EQ(linux_events.size(), 1u);
	const auto& windows_file = std::get<FatalCrash>(windows_events[0].event).source_file;
	const auto& linux_file   = std::get<FatalCrash>(linux_events[0].event).source_file;
	EXPECT_EQ(windows_file, "src/loader/runtimeLinker.cpp");
	EXPECT_EQ(windows_file, linux_file);
}

// A process killed mid-write can leave a report incomplete.
TEST(LogAnalyzerParser, DropsATruncatedCrashBlockInsteadOfGuessing) {
	const auto events =
	    ParseText("--- Build ---\n"
		          "Official build X\n"
		          "--- Fatal Error ---\n"
		          "Not implemented (x)"); // No trailing newline, no " in file:line" ever.

	EXPECT_TRUE(events.empty());
}

// LoadExec() can continue the same log file across more than one run.
TEST(LogAnalyzerParser, TwoLoadExecSegmentsProduceTwoCrashEvents) {
	const auto events = ParseText("--- Build ---\n"
	                              "Official build X\n"
	                              "--- Error ---\n"
	                              "first in src/a.cpp:1\n"
	                              "--- Build ---\n"
	                              "Official build Y\n"
	                              "--- Fatal Error ---\n"
	                              "second in src/b.cpp:2\n");

	ASSERT_EQ(events.size(), 2u);
	EXPECT_EQ(std::get<FatalCrash>(events[0].event).source_file, "src/a.cpp");
	EXPECT_EQ(std::get<FatalCrash>(events[1].event).source_file, "src/b.cpp");
}

TEST(LogAnalyzerAnalyzer, GroupsSameLocationDespiteDifferentMessageAndBuild) {
	const std::vector<LogEvent> events = {
	    {1, FatalCrash {.title       = "Error",
		                .build_label = "build A",
		                .message     = "value=1",
		                .source_file = "src/foo.cpp",
		                .source_line = 10}},
	    {2, FatalCrash {.title       = "Error",
		                .build_label = "build B",
		                .message     = "value=999", // A different runtime value, same call site.
		                .source_file = "src/foo.cpp",
		                .source_line = 10}},
	};

	const auto findings = Analyze(events);

	ASSERT_EQ(findings.size(), 1u);
	EXPECT_EQ(findings[0].occurrence_count, 2u);
	EXPECT_EQ(findings[0].first_line_number, 1u);
	EXPECT_EQ(std::get<FatalCrash>(findings[0].example).message, "value=1"); // The first one seen.
}

TEST(LogAnalyzerAnalyzer, TreatsADifferentSourceLineAsADistinctFinding) {
	const std::vector<LogEvent> events = {
	    {1, FatalCrash {.title = "Error", .source_file = "src/foo.cpp", .source_line = 10}},
	    {2, FatalCrash {.title = "Error", .source_file = "src/foo.cpp", .source_line = 11}},
	};

	EXPECT_EQ(Analyze(events).size(), 2u);
}

TEST(LogAnalyzerAnalyzer, CountsARepeatedUnresolvedImportSymbol) {
	const std::vector<LogEvent> events = {
	    {1, UnresolvedImport {.symbol = "abc", .program = "eboot.bin"}},
	    {2, UnresolvedImport {.symbol = "abc", .program = "eboot.bin"}},
	};

	const auto findings = Analyze(events);

	ASSERT_EQ(findings.size(), 1u);
	EXPECT_EQ(findings[0].occurrence_count, 2u);
}

TEST(LogAnalyzerAnalyzer, PreservesFirstSeenOrder) {
	const std::vector<LogEvent> events = {
	    {1, UnresolvedImport {.symbol = "first", .program = "p"}},
	    {2, FatalCrash {.title = "Error", .source_file = "src/foo.cpp", .source_line = 1}},
	    {3, UnresolvedImport {.symbol = "third", .program = "p"}},
	};

	const auto findings = Analyze(events);

	ASSERT_EQ(findings.size(), 3u);
	EXPECT_EQ(std::get<UnresolvedImport>(findings[0].example).symbol, "first");
	EXPECT_NE(std::get_if<FatalCrash>(&findings[1].example), nullptr);
	EXPECT_EQ(std::get<UnresolvedImport>(findings[2].example).symbol, "third");
}

std::vector<Finding> OneCrashAndTwoImportsOnTheSameProgram() {
	return {
	    Finding {.signature         = FatalCrashSignature {.title       = "FatalError",
		                                                   .source_file = "src/foo.cpp",
		                                                   .source_line = 10},
		         .occurrence_count  = 1,
		         .first_line_number = 5,
		         .example           = FatalCrash {.title       = "FatalError",
		                                          .message     = "boom",
		                                          .source_file = "src/foo.cpp",
		                                          .source_line = 10}},
	    Finding {.occurrence_count  = 1,
		         .first_line_number = 1,
		         .example           = UnresolvedImport {.symbol = "symA", .program = "eboot.bin"}},
	    Finding {.occurrence_count  = 1,
		         .first_line_number = 2,
		         .example           = UnresolvedImport {.symbol = "symB", .program = "eboot.bin"}},
	};
}

TEST(LogAnalyzerFormatSummary, ShowsAFatalVerdictWithTheCrashBeforeTheImports) {
	const auto text = FormatSummary(OneCrashAndTwoImportsOnTheSameProgram());

	EXPECT_NE(text.find("ended in a fatal crash"), std::string::npos);
	const auto crash_pos   = text.find("Fatal crash");
	const auto imports_pos = text.find("Unresolved imports");
	ASSERT_NE(crash_pos, std::string::npos);
	ASSERT_NE(imports_pos, std::string::npos);
	EXPECT_LT(crash_pos, imports_pos);
}

TEST(LogAnalyzerFormatSummary, IndentsTheContinuationLinesOfAMultiLineMessage) {
	const std::vector<LogEvent> events = {
	    {1, FatalCrash {.title       = "Error",
	                    .message     = "first line\nThe Vulkan spec states: second line",
	                    .source_file = "src/a.cpp",
	                    .source_line = 1}},
	};

	const auto summary = FormatSummary(Analyze(events));

	EXPECT_NE(summary.find("      first line\n      The Vulkan spec states: second line"),
	          std::string::npos);
}

TEST(LogAnalyzerFormatSummary, ReportsNoFatalErrorReportWithoutClaimingTheRunWasHealthy) {
	std::vector<Finding> findings = OneCrashAndTwoImportsOnTheSameProgram();
	findings.erase(findings.begin()); // Drop the crash, keep only the two imports.

	const auto text = FormatSummary(findings);

	EXPECT_NE(text.find("no fatal error report found in this log"), std::string::npos);
	EXPECT_NE(text.find("may still have been killed without writing one"), std::string::npos);
	EXPECT_EQ(text.find("ended in a fatal crash"), std::string::npos);
}

TEST(LogAnalyzerFormatSummary, DefaultViewGroupsImportsByProgramWithoutNamingSymbols) {
	const auto text = FormatSummary(OneCrashAndTwoImportsOnTheSameProgram());

	EXPECT_NE(text.find("2 from eboot.bin"), std::string::npos);
	EXPECT_EQ(text.find("symA"), std::string::npos);
	EXPECT_EQ(text.find("symB"), std::string::npos);
}

TEST(LogAnalyzerFormatSummary, VerboseViewListsEachSymbol) {
	FormatOptions options;
	options.show_import_symbols = true;

	const auto text = FormatSummary(OneCrashAndTwoImportsOnTheSameProgram(), options);

	EXPECT_NE(text.find("symA"), std::string::npos);
	EXPECT_NE(text.find("symB"), std::string::npos);
}

TEST(LogAnalyzerFormatSummary, EmitsAnsiColorCodesOnlyWhenEnabled) {
	const auto findings = OneCrashAndTwoImportsOnTheSameProgram();

	FormatOptions with_color;
	with_color.use_color = true;
	EXPECT_NE(FormatSummary(findings, with_color).find("\033["), std::string::npos);

	FormatOptions without_color;
	without_color.use_color = false;
	EXPECT_EQ(FormatSummary(findings, without_color).find("\033["), std::string::npos);
}

TEST(LogAnalyzerFormatJson, ProducesJsonNlohmannCanParseBack) {
	const auto json_text = FormatJson(OneCrashAndTwoImportsOnTheSameProgram());

	const auto parsed = nlohmann::json::parse(json_text, nullptr, /*allow_exceptions=*/false);
	ASSERT_FALSE(parsed.is_discarded()) << "FormatJson() did not produce valid JSON";
	ASSERT_TRUE(parsed.contains("findings"));
	ASSERT_EQ(parsed["findings"].size(), 3u);

	const auto& crash_entry = parsed["findings"][0];
	EXPECT_EQ(crash_entry["kind"], "fatal_crash");
	EXPECT_EQ(crash_entry["source_line"], 10);
	EXPECT_EQ(crash_entry["occurrence_count"], 1);

	const auto& import_entry = parsed["findings"][1];
	EXPECT_EQ(import_entry["kind"], "unresolved_import");
	EXPECT_EQ(import_entry["symbol"], "symA");
}

} // namespace

int main(int argc, char** argv) {
	testing::InitGoogleTest(&argc, argv);
	return RUN_ALL_TESTS();
}
