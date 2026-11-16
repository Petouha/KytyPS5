#include "log_analyzer/analyzer.h"
#include "log_analyzer/parser.h"

#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <optional>
#include <string>

#if defined(_WIN32)
#include <io.h>
#define KYTY_ISATTY _isatty
#define KYTY_FILENO _fileno
#else
#include <unistd.h>
#define KYTY_ISATTY isatty
#define KYTY_FILENO fileno
#endif

namespace {

void PrintUsage() {
	::printf("kyty_log_analyzer <log> [--json <file>] [--verbose] [--no-color]\n\n");
	::printf("Reads a KytyPS5 log (by default, _kyty.txt) and prints a summary of the\n");
	::printf("fatal crashes and unresolved imports it contains.\n\n");
	::printf("Options:\n");
	::printf("  --json <file>   Also write the same findings as JSON to <file>.\n");
	::printf("  --verbose       List every unresolved-import symbol instead of a count\n");
	::printf("                  per module.\n");
	::printf("  --no-color      Never colorize the summary, even on a terminal.\n");
}

struct Options {
	std::string                log_path;
	std::optional<std::string> json_path;
	bool                       show_help      = false;
	bool                       verbose        = false;
	bool                       force_no_color = false;
};

// --no-color wins, then https://no-color.org's NO_COLOR, then whether
// stdout is actually a terminal (never color a redirect into a file).
bool ShouldUseColor(bool force_no_color) {
	if (force_no_color || std::getenv("NO_COLOR") != nullptr) {
		return false;
	}
	return KYTY_ISATTY(KYTY_FILENO(stdout)) != 0;
}

// Same argv-loop idiom as kyty_emulator's own ParseArgs() (src/main.cpp).
bool ParseArgs(int argc, char** argv, Options& options) {
	for (int i = 1; i < argc; i++) {
		const std::string arg = argv[i];

		if (arg == "--help" || arg == "-h") {
			options.show_help = true;
			continue;
		}

		if (arg == "--json") {
			if (i + 1 >= argc) {
				std::cerr << "missing value for --json\n";
				return false;
			}
			options.json_path = argv[++i];
			continue;
		}

		if (arg == "--verbose") {
			options.verbose = true;
			continue;
		}

		if (arg == "--no-color") {
			options.force_no_color = true;
			continue;
		}

		if (!options.log_path.empty()) {
			std::cerr << "only one log file may be given\n";
			return false;
		}
		options.log_path = arg;
	}

	if (!options.show_help && options.log_path.empty()) {
		std::cerr << "missing <log> argument\n";
		return false;
	}
	return true;
}

} // namespace

int main(int argc, char** argv) {
	if (argc < 2) {
		PrintUsage();
		return 0;
	}

	Options options;
	if (!ParseArgs(argc, argv, options)) {
		PrintUsage();
		return 1;
	}
	if (options.show_help) {
		PrintUsage();
		return 0;
	}

	std::ifstream input(options.log_path);
	if (!input) {
		std::cerr << "cannot open " << options.log_path << "\n";
		return 1;
	}

	const auto events   = LogAnalyzer::Parse(input);
	const auto findings = LogAnalyzer::Analyze(events);

	const LogAnalyzer::FormatOptions format_options {
	    .show_import_symbols = options.verbose,
	    .use_color           = ShouldUseColor(options.force_no_color),
	};
	std::cout << LogAnalyzer::FormatSummary(findings, format_options);

	// Unlike the log's content, which is never ours to judge, a requested
	// JSON file we can't write is a real failure.
	if (options.json_path) {
		std::ofstream output(*options.json_path);
		if (!output) {
			std::cerr << "cannot write " << *options.json_path << "\n";
			return 1;
		}
		output << LogAnalyzer::FormatJson(findings);
	}

	return 0;
}
