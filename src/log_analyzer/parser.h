#ifndef EMULATOR_SRC_LOG_ANALYZER_PARSER_H_
#define EMULATOR_SRC_LOG_ANALYZER_PARSER_H_

#include <cstdint>
#include <istream>
#include <string>
#include <variant>
#include <vector>

namespace LogAnalyzer {

// One EXIT()/EXIT_IF()/EXIT_NOT_IMPLEMENTED() report (see Common::DbgReport,
// common/assert.cpp).
struct FatalCrash {
	std::string title;       // "Error" or "FatalError".
	std::string build_label; // e.g. "Official build KytyPS5-2026-11-11-bc934ef".
	std::string message;     // No trailing " in file:line"; that's source_file/source_line below.
	std::string source_file; // Forward-slash form, so a Windows build's path and a Linux build's
	                         // path for the same crash normalize to the same value.
	uint32_t    source_line = 0;
};

// One "Unresolved import stub called" line (see Loader::UnresolvedImportStub,
// loader/runtimeLinker.cpp). Unlike FatalCrash, the emulator keeps running.
struct UnresolvedImport {
	std::string symbol;
	std::string program;
	std::string import_type; // e.g. "Func". Kept as text, not Loader::SymbolType: this tool
	std::string import_bind; // e.g. "Global". must not depend on the loader.
	bool        is_bad_record = false; // The "<bad-record>" fallback form.
};

// Adding a new kind later: add its struct, add it here, and handle it in
// every std::visit over Event (an incomplete visit won't compile).
using Event = std::variant<FatalCrash, UnresolvedImport>;

struct LogEvent {
	uint32_t line_number = 0; // 1-based; display only, never part of an event's identity.
	Event    event;
};

// Streams "input" line by line (a real log can be several MB) and returns
// every FatalCrash/UnresolvedImport found, in file order. Other lines (game
// logs, shader cache stats, warnings...) are skipped.
std::vector<LogEvent> Parse(std::istream& input);

} // namespace LogAnalyzer

#endif // EMULATOR_SRC_LOG_ANALYZER_PARSER_H_
