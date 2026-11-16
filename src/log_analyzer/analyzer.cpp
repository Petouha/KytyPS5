#include "log_analyzer/analyzer.h"

#include <algorithm>
#include <fmt/format.h>
#include <nlohmann/json.hpp>
#include <string_view>
#include <type_traits>
#include <utility>

namespace LogAnalyzer {

namespace {
using Json = nlohmann::json;

// Continuation lines of a multi-line message line up under the first one.
std::string IndentContinuationLines(const std::string& text, std::string_view indent) {
	std::string result;
	for (const char c: text) {
		result += c;
		if (c == '\n') {
			result += indent;
		}
	}
	return result;
}
} // namespace

ErrorSignature SignatureOf(const Event& event) {
	return std::visit(
	    [](const auto& payload) -> ErrorSignature {
		    using T = std::decay_t<decltype(payload)>;
		    if constexpr (std::is_same_v<T, FatalCrash>) {
			    return FatalCrashSignature {
			        .title       = payload.title,
			        .source_file = payload.source_file,
			        .source_line = payload.source_line,
			    };
		    } else {
			    static_assert(std::is_same_v<T, UnresolvedImport>);
			    return UnresolvedImportSignature {
			        .symbol  = payload.symbol,
			        .program = payload.program,
			    };
		    }
	    },
	    event);
}

std::vector<Finding> Analyze(const std::vector<LogEvent>& events) {
	std::vector<Finding> findings;

	for (const auto& log_event: events) {
		auto signature = SignatureOf(log_event.event);

		auto existing =
		    std::find_if(findings.begin(), findings.end(),
			             [&signature](const Finding& f) { return f.signature == signature; });
		if (existing != findings.end()) {
			existing->occurrence_count++;
			continue;
		}

		findings.push_back(Finding {
		    .signature         = std::move(signature),
		    .occurrence_count  = 1,
		    .first_line_number = log_event.line_number,
		    .example           = log_event.event,
		});
	}

	return findings;
}

namespace {

// Resolved once per FormatSummary() call; every code point below is empty
// when options.use_color is false, so callers never need an "if (use_color)"
// of their own.
struct Palette {
	std::string_view bold;
	std::string_view reset;
	std::string_view red;
	std::string_view yellow;
	std::string_view green;
	std::string_view dim;
};

Palette MakePalette(bool enabled) {
	if (!enabled) {
		return {};
	}
	return {
	    .bold   = "\033[1m",
	    .reset  = "\033[0m",
	    .red    = "\033[31m",
	    .yellow = "\033[33m",
	    .green  = "\033[32m",
	    .dim    = "\033[2m",
	};
}

const FatalCrash* AsFatalCrash(const Finding& finding) {
	return std::get_if<FatalCrash>(&finding.example);
}

const UnresolvedImport* AsUnresolvedImport(const Finding& finding) {
	return std::get_if<UnresolvedImport>(&finding.example);
}

// Groups the UnresolvedImport findings by program, in the order each program
// was first seen, so the default view can show one count per module instead
// of one illegible NID per line.
std::vector<std::pair<std::string, std::vector<const Finding*>>>
GroupImportsByProgram(const std::vector<Finding>& findings) {
	std::vector<std::pair<std::string, std::vector<const Finding*>>> groups;

	for (const auto& finding: findings) {
		const auto* import = AsUnresolvedImport(finding);
		if (import == nullptr) {
			continue;
		}
		const std::string& program = import->is_bad_record ? "<bad-record>" : import->program;

		auto existing = std::find_if(groups.begin(), groups.end(), [&program](const auto& group) {
			return group.first == program;
		});
		if (existing == groups.end()) {
			groups.push_back({program, {&finding}});
		} else {
			existing->second.push_back(&finding);
		}
	}

	return groups;
}

} // namespace

std::string FormatSummary(const std::vector<Finding>& findings, const FormatOptions& options) {
	const Palette palette = MakePalette(options.use_color);

	std::vector<const Finding*> crashes;
	uint32_t                    import_occurrences = 0;
	for (const auto& finding: findings) {
		if (AsFatalCrash(finding) != nullptr) {
			crashes.push_back(&finding);
		} else {
			import_occurrences += finding.occurrence_count;
		}
	}

	std::string text = fmt::format("{}=== kyty_log_analyzer ==={}\n", palette.bold, palette.reset);

	if (crashes.empty()) {
		text +=
		    fmt::format("{}Outcome: no fatal error report found in this log.{}\n"
		                "{}(The process may still have been killed without writing one.){}\n",
		                palette.green, palette.reset, palette.dim, palette.reset);
	} else {
		text += fmt::format("{}Outcome: this run ended in a fatal crash.{}\n", palette.red,
		                    palette.reset);
	}

	if (!crashes.empty()) {
		text +=
		    fmt::format("\n{}Fatal crash{} ({}):\n", palette.bold, palette.reset, crashes.size());
		for (const auto* finding: crashes) {
			const auto& crash = *AsFatalCrash(*finding);
			text += fmt::format("  {}[{}] {}:{}{}\n", palette.red, crash.title, crash.source_file,
			                    crash.source_line, palette.reset);
			text += fmt::format("      {}\n", IndentContinuationLines(crash.message, "      "));
			text += fmt::format("      {}(first seen at log line {}){}\n", palette.dim,
			                    finding->first_line_number, palette.reset);
		}
	}

	const auto import_groups = GroupImportsByProgram(findings);
	if (!import_groups.empty()) {
		text += fmt::format("\n{}Unresolved imports{} ({}, usually not fatal on their own):\n",
		                    palette.yellow, palette.reset, import_occurrences);
		for (const auto& [program, group_findings]: import_groups) {
			uint32_t count = 0;
			for (const auto* finding: group_findings) {
				count += finding->occurrence_count;
			}

			if (!options.show_import_symbols) {
				text += fmt::format("  - {} from {}\n", count, program);
				continue;
			}

			text += fmt::format("  - {} ({}):\n", program, count);
			for (const auto* finding: group_findings) {
				const auto& import = *AsUnresolvedImport(*finding);
				text += fmt::format("      {}\n",
				                    import.is_bad_record ? "<bad-record>" : import.symbol);
			}
		}
		if (!options.show_import_symbols) {
			text += fmt::format("  {}(use --verbose to list each symbol){}\n", palette.dim,
			                    palette.reset);
		}
	}

	return text;
}

std::string FormatJson(const std::vector<Finding>& findings) {
	Json entries = Json::array();

	for (const auto& finding: findings) {
		Json entry = std::visit(
		    [](const auto& payload) -> Json {
			    using T = std::decay_t<decltype(payload)>;
			    if constexpr (std::is_same_v<T, FatalCrash>) {
				    return Json {
				        {"kind", "fatal_crash"},
				        {"title", payload.title},
				        {"source_file", payload.source_file},
				        {"source_line", payload.source_line},
				        {"message", payload.message},
				    };
			    } else {
				    return Json {
				        {"kind", "unresolved_import"},
				        {"symbol", payload.is_bad_record ? "<bad-record>" : payload.symbol},
				        {"program", payload.program},
				        {"import_type", payload.import_type},
				        {"import_bind", payload.import_bind},
				    };
			    }
		    },
		    finding.example);

		entry["occurrence_count"]  = finding.occurrence_count;
		entry["first_line_number"] = finding.first_line_number;
		entries.push_back(std::move(entry));
	}

	Json root;
	root["findings"] = std::move(entries);
	return root.dump(2);
}

} // namespace LogAnalyzer
