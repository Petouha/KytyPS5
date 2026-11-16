#ifndef EMULATOR_SRC_LOG_ANALYZER_ANALYZER_H_
#define EMULATOR_SRC_LOG_ANALYZER_ANALYZER_H_

#include "log_analyzer/parser.h"

#include <cstdint>
#include <string>
#include <variant>
#include <vector>

namespace LogAnalyzer {

// The identity of a FatalCrash: the exact call site, stable even when the
// free-form message carries a different runtime value each time (e.g.
// "base=6 ..." vs "base=3 ..." from the same EXIT() call).
struct FatalCrashSignature {
	std::string title;
	std::string source_file;
	uint32_t    source_line = 0;

	bool operator==(const FatalCrashSignature&) const = default;
};

// The identity of an UnresolvedImport: which symbol is missing from which
// module, not patch_vaddr/jmprela_index, which differ between runs of the
// same game.
struct UnresolvedImportSignature {
	std::string symbol;
	std::string program;

	bool operator==(const UnresolvedImportSignature&) const = default;
};

// Same discipline as Event in parser.h: a new kind needs a struct here too.
using ErrorSignature = std::variant<FatalCrashSignature, UnresolvedImportSignature>;

ErrorSignature SignatureOf(const Event& event);

// Every LogEvent sharing a signature, collapsed into one entry: a count and
// the first occurrence to show.
struct Finding {
	ErrorSignature signature;
	uint32_t       occurrence_count  = 0;
	uint32_t       first_line_number = 0;
	Event          example;
};

// Groups "events" (as produced by Parse()) by ErrorSignature, in the order
// each signature was first seen.
std::vector<Finding> Analyze(const std::vector<LogEvent>& events);

// Presentation choices for FormatSummary(): how findings are displayed,
// never what counts as a finding.
struct FormatOptions {
	bool show_import_symbols = false; // List every symbol instead of a count per module.
	bool use_color           = false; // The CLI decides this from isatty()/NO_COLOR, not here.
};

// A short human-readable report for stdout: a verdict, then the crashes,
// then the imports.
std::string FormatSummary(const std::vector<Finding>& findings, const FormatOptions& options = {});

// The same findings as JSON, for the CLI's "--json" option.
std::string FormatJson(const std::vector<Finding>& findings);

} // namespace LogAnalyzer

#endif // EMULATOR_SRC_LOG_ANALYZER_ANALYZER_H_
