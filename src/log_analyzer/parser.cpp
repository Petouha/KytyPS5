#include "log_analyzer/parser.h"

#include <algorithm>
#include <optional>
#include <regex>

namespace LogAnalyzer {

namespace {

// Reads one line and advances the shared line counter, stripping a trailing
// '\r' so both \n and \r\n logs parse the same way.
bool NextLine(std::istream& input, std::string& out, uint32_t& line_number) {
	if (!std::getline(input, out)) {
		return false;
	}
	line_number++;
	if (!out.empty() && out.back() == '\r') {
		out.pop_back();
	}
	return true;
}

// Rewrites a __FILE__ path to its "src/..." form, so the same crash from a
// Linux build and a Windows build normalizes to the same source_file.
std::string NormalizeSourcePath(std::string path) {
	std::replace(path.begin(), path.end(), '\\', '/');
	static const std::string marker = "src/";
	if (auto pos = path.find(marker); pos != std::string::npos) {
		return path.substr(pos);
	}
	return path;
}

// The " in <file>:<line>" suffix Common::DbgReport always appends. Usually on
// the same line as the message, but a few EXIT() call sites embed their own
// '\n' and push it onto its own line, so this pattern matches both.
const std::regex g_crash_location_pattern(R"(^(.*) in (\S+):(\d+)\s*$)");

// The two shapes Loader::UnresolvedImportStub logs: the normal case, and the
// "<bad-record>" fallback for an out-of-range record_id.
const std::regex g_unresolved_import_pattern(
    R"(^Unresolved import stub called \[\d+\]: patch_vaddr=0x[0-9a-fA-F]+ )"
    R"(jmprela_index=\d+ symbol=(.*) type=(\S+) bind=(\S+) program=(.*)$)");
const std::regex g_unresolved_import_bad_record_pattern(
    R"(^Unresolved import stub called \[\d+\]: record_id=\d+ symbol=<bad-record>$)");

std::optional<UnresolvedImport> ParseUnresolvedImport(const std::string& line) {
	std::smatch match;
	if (std::regex_match(line, match, g_unresolved_import_pattern)) {
		return UnresolvedImport {
		    .symbol        = match[1].str(),
		    .program       = match[4].str(),
		    .import_type   = match[2].str(),
		    .import_bind   = match[3].str(),
		    .is_bad_record = false,
		};
	}
	if (std::regex_match(line, g_unresolved_import_bad_record_pattern)) {
		UnresolvedImport result;
		result.is_bad_record = true;
		return result;
	}
	return std::nullopt;
}

// One line is the common case; this is slack for the rare EXIT() call that
// embeds its own '\n'. Past it, the report is treated as truncated and
// dropped rather than guessed at.
constexpr uint32_t kMaxMessageLines = 5;

struct CrashLocation {
	std::string message;
	std::string source_file;
	uint32_t    source_line = 0;
};

std::optional<CrashLocation> ReadCrashLocation(std::istream& input, uint32_t& line_number) {
	CrashLocation result;
	std::string   line;
	for (uint32_t i = 0; i < kMaxMessageLines && NextLine(input, line, line_number); i++) {
		std::smatch match;
		if (std::regex_match(line, match, g_crash_location_pattern)) {
			const auto& prefix = match[1];
			if (!result.message.empty() && !prefix.str().empty()) {
				result.message += '\n';
			}
			result.message += prefix.str();
			result.source_file = NormalizeSourcePath(match[2].str());
			result.source_line = static_cast<uint32_t>(std::stoul(match[3].str()));
			return result;
		}
		if (!result.message.empty()) {
			result.message += '\n';
		}
		result.message += line;
	}
	return std::nullopt; // Truncated file, or a report shape this parser does not know yet.
}

} // namespace

std::vector<LogEvent> Parse(std::istream& input) {
	std::vector<LogEvent> events;
	std::string           line;
	uint32_t              line_number = 0;

	while (NextLine(input, line, line_number)) {
		if (line == "--- Build ---") {
			const uint32_t event_line = line_number;

			std::string build_label;
			std::string title_line;
			if (!NextLine(input, build_label, line_number) ||
			    !NextLine(input, title_line, line_number)) {
				break; // File ends right after "--- Build ---": nothing more to read.
			}

			std::string title;
			if (title_line == "--- Error ---") {
				title = "Error";
			} else if (title_line == "--- Fatal Error ---") {
				title = "FatalError";
			} else {
				continue; // Not a report shape this parser knows.
			}

			if (auto location = ReadCrashLocation(input, line_number)) {
				events.push_back({event_line, FatalCrash {
				                                  .title       = std::move(title),
				                                  .build_label = std::move(build_label),
				                                  .message     = std::move(location->message),
				                                  .source_file = std::move(location->source_file),
				                                  .source_line = location->source_line,
				                              }});
			}
			continue;
		}

		if (line.starts_with("Unresolved import stub called")) {
			if (auto import = ParseUnresolvedImport(line)) {
				events.push_back({line_number, std::move(*import)});
			}
			continue;
		}
	}

	return events;
}

} // namespace LogAnalyzer
