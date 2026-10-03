/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package reva.tools.sourcemetadata;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import ghidra.program.database.sourcemap.SourceFile;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.listing.Program;
import ghidra.program.model.sourcemap.SourceFileManager;
import ghidra.program.model.sourcemap.SourceMapEntry;
import io.modelcontextprotocol.server.McpSyncServer;
import io.modelcontextprotocol.spec.McpSchema;
import reva.tools.AbstractToolProvider;
import reva.util.AddressUtil;
import reva.util.SchemaUtil;

/**
 * Generic read-only source/debug mapping tools backed by Ghidra's source map.
 *
 * <p>This intentionally does not hardcode DWARF, PDB, Rust, Go, or any challenge
 * convention. Any debug importer that populates Ghidra's SourceFileManager can
 * benefit from the same MCP interface.</p>
 */
public class SourceMetadataToolProvider extends AbstractToolProvider {
    private static final int DEFAULT_MAX_COUNT = 100;
    private static final int HARD_MAX_COUNT = 500;

    public SourceMetadataToolProvider(McpSyncServer server) {
        super(server);
    }

    @Override
    public void registerTools() {
        registerListSourceFilesTool();
        registerSourceMappingsTool();
    }

    private void registerListSourceFilesTool() {
        Map<String, Object> properties = new LinkedHashMap<>();
        properties.put("programPath",
            SchemaUtil.stringProperty("Path in the Ghidra Project to the program"));
        properties.put("query",
            SchemaUtil.stringProperty("Optional case-insensitive substring filter on full source path or filename"));
        properties.put("mappedOnly", SchemaUtil.booleanPropertyWithDefault(
            "Return only source files with address mappings", false));
        properties.put("startIndex", SchemaUtil.integerPropertyWithDefault(
            "Starting index after filtering", 0));
        properties.put("maxCount", SchemaUtil.integerPropertyWithDefault(
            "Maximum files to return (hard cap 500)", DEFAULT_MAX_COUNT));

        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("list-source-files")
            .title("List Source Files")
            .description("List source files known to Ghidra's generic source map, including whether each file has address mappings. " +
                "Works with source metadata imported from supported debug formats without assuming DWARF or PDB.")
            .inputSchema(createSchema(properties, List.of("programPath")))
            .build();

        registerTool(tool, (exchange, request) -> {
            Program program = getProgramFromArgs(request);
            SourceFileManager manager = program.getSourceFileManager();
            String query = getOptionalString(request, "query", "").toLowerCase(Locale.ROOT);
            boolean mappedOnly = getOptionalBoolean(request, "mappedOnly", false);
            int startIndex = Math.max(0, getOptionalInt(request, "startIndex", 0));
            int maxCount = boundedPositive(
                getOptionalInt(request, "maxCount", DEFAULT_MAX_COUNT), "maxCount");

            Set<SourceFile> mapped = new HashSet<>(manager.getMappedSourceFiles());
            List<SourceFile> files = new ArrayList<>(manager.getAllSourceFiles());
            files.sort(Comparator.comparing(SourceFile::getPath));

            List<SourceFile> filtered = new ArrayList<>();
            for (SourceFile file : files) {
                boolean isMapped = mapped.contains(file);
                if (mappedOnly && !isMapped) {
                    continue;
                }
                String path = file.getPath().toLowerCase(Locale.ROOT);
                String filename = file.getFilename().toLowerCase(Locale.ROOT);
                if (!query.isEmpty() && !path.contains(query) && !filename.contains(query)) {
                    continue;
                }
                filtered.add(file);
            }

            int endIndex = Math.min(startIndex + maxCount, filtered.size());
            List<Map<String, Object>> page = new ArrayList<>();
            if (startIndex < filtered.size()) {
                for (int i = startIndex; i < endIndex; i++) {
                    SourceFile file = filtered.get(i);
                    page.add(formatSourceFile(file, mapped.contains(file)));
                }
            }

            Map<String, Object> result = new LinkedHashMap<>();
            result.put("programPath", program.getDomainFile().getPathname());
            result.put("totalSourceFiles", files.size());
            result.put("mappedSourceFiles", mapped.size());
            result.put("filteredCount", filtered.size());
            result.put("startIndex", startIndex);
            result.put("requestedCount", maxCount);
            result.put("actualCount", page.size());
            result.put("nextStartIndex", startIndex + page.size());
            result.put("hasMore", endIndex < filtered.size());
            result.put("files", page);
            return createJsonResult(result);
        });
    }

    private void registerSourceMappingsTool() {
        Map<String, Object> properties = new LinkedHashMap<>();
        properties.put("programPath",
            SchemaUtil.stringProperty("Path in the Ghidra Project to the program"));
        properties.put("sourcePath",
            SchemaUtil.stringProperty("Exact source path, or an unambiguous source filename"));
        properties.put("addressOrSymbol",
            SchemaUtil.stringProperty("Address or symbol whose source mappings should be returned"));
        properties.put("startIndex", SchemaUtil.integerPropertyWithDefault(
            "Starting mapping index", 0));
        properties.put("maxCount", SchemaUtil.integerPropertyWithDefault(
            "Maximum mappings to return (hard cap 500)", DEFAULT_MAX_COUNT));

        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("get-source-mappings")
            .title("Get Source Mappings")
            .description("Get generic source-to-address mappings either for one source file or for an address/symbol. " +
                "Supply exactly one of sourcePath or addressOrSymbol. This is read-only and format-neutral.")
            .inputSchema(createSchema(properties, List.of("programPath")))
            .build();

        registerTool(tool, (exchange, request) -> {
            Program program = getProgramFromArgs(request);
            SourceFileManager manager = program.getSourceFileManager();
            String sourcePath = getOptionalString(request, "sourcePath", null);
            String addressText = getOptionalString(request, "addressOrSymbol", null);
            if ((sourcePath == null) == (addressText == null)) {
                return createErrorResult("Supply exactly one of sourcePath or addressOrSymbol");
            }

            int startIndex = Math.max(0, getOptionalInt(request, "startIndex", 0));
            int maxCount = boundedPositive(
                getOptionalInt(request, "maxCount", DEFAULT_MAX_COUNT), "maxCount");

            List<SourceMapEntry> entries;
            String resolvedSourcePath = null;
            String resolvedAddress = null;

            if (sourcePath != null) {
                SourceFile sourceFile = resolveSourceFile(manager, sourcePath);
                if (sourceFile == null) {
                    return createErrorResult("Source file not found: " + sourcePath +
                        ". Use list-source-files to discover exact paths.");
                }
                resolvedSourcePath = sourceFile.getPath();
                entries = manager.getSourceMapEntries(sourceFile);
                if (!entries.isEmpty()) {
                    followRead(program, entries.get(0).getBaseAddress());
                }
            }
            else {
                Address address = getAddressFromArgs(request, program, "addressOrSymbol");
                resolvedAddress = AddressUtil.formatAddress(address);
                entries = manager.getSourceMapEntries(address);
                followRead(program, address);
            }

            int endIndex = Math.min(startIndex + maxCount, entries.size());
            List<Map<String, Object>> page = new ArrayList<>();
            if (startIndex < entries.size()) {
                for (int i = startIndex; i < endIndex; i++) {
                    page.add(formatMapping(entries.get(i)));
                }
            }

            Map<String, Object> result = new LinkedHashMap<>();
            result.put("programPath", program.getDomainFile().getPathname());
            if (resolvedSourcePath != null) {
                result.put("sourcePath", resolvedSourcePath);
            }
            if (resolvedAddress != null) {
                result.put("address", resolvedAddress);
            }
            result.put("mappingCount", entries.size());
            result.put("startIndex", startIndex);
            result.put("requestedCount", maxCount);
            result.put("actualCount", page.size());
            result.put("nextStartIndex", startIndex + page.size());
            result.put("hasMore", endIndex < entries.size());
            result.put("mappings", page);
            return createJsonResult(result);
        });
    }

    private static Map<String, Object> formatSourceFile(SourceFile file, boolean mapped) {
        Map<String, Object> info = new LinkedHashMap<>();
        info.put("path", file.getPath());
        info.put("filename", file.getFilename());
        info.put("idType", file.getIdType().name());
        String id = file.getIdAsString();
        if (id != null && !id.isEmpty()) {
            info.put("id", id);
        }
        info.put("mapped", mapped);
        return info;
    }

    private static Map<String, Object> formatMapping(SourceMapEntry entry) {
        Map<String, Object> info = new LinkedHashMap<>();
        SourceFile sourceFile = entry.getSourceFile();
        info.put("sourcePath", sourceFile.getPath());
        info.put("filename", sourceFile.getFilename());
        info.put("line", entry.getLineNumber());
        info.put("baseAddress", AddressUtil.formatAddress(entry.getBaseAddress()));
        info.put("length", entry.getLength());
        AddressRange range = entry.getRange();
        if (range != null) {
            info.put("endAddress", AddressUtil.formatAddress(range.getMaxAddress()));
        }
        return info;
    }

    private static SourceFile resolveSourceFile(SourceFileManager manager, String requested) {
        List<SourceFile> all = manager.getAllSourceFiles();
        for (SourceFile file : all) {
            if (file.getPath().equals(requested)) {
                return file;
            }
        }

        List<SourceFile> filenameMatches = new ArrayList<>();
        for (SourceFile file : all) {
            if (file.getFilename().equals(requested)) {
                filenameMatches.add(file);
            }
        }
        if (filenameMatches.size() == 1) {
            return filenameMatches.get(0);
        }
        if (filenameMatches.size() > 1) {
            String choices = filenameMatches.stream()
                .limit(10)
                .map(SourceFile::getPath)
                .reduce((a, b) -> a + ", " + b)
                .orElse("");
            throw new IllegalArgumentException("Ambiguous source filename '" + requested +
                "'. Use an exact path. Candidates: " + choices);
        }
        return null;
    }

    private static int boundedPositive(int value, String name) {
        if (value <= 0) {
            throw new IllegalArgumentException(name + " must be greater than zero");
        }
        return Math.min(value, HARD_MAX_COUNT);
    }
}
