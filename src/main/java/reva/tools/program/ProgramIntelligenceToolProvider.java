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
package reva.tools.program;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.reloc.RelocationTable;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import io.modelcontextprotocol.server.McpSyncServer;
import io.modelcontextprotocol.spec.McpSchema;
import reva.tools.AbstractToolProvider;
import reva.util.AddressUtil;
import reva.util.SchemaUtil;

/**
 * Read-only program-level intelligence that gives an MCP client a compact,
 * format-neutral view of the binary before deeper analysis.
 *
 * <p>This intentionally reports Ghidra facts rather than inferred labels such
 * as "PIE", "NX", or "full RELRO". Those conclusions are format-specific and
 * can be made by the client from the returned metadata plus existing import,
 * memory, and symbol tools.</p>
 */
public class ProgramIntelligenceToolProvider extends AbstractToolProvider {
    private static final int DEFAULT_MAX_BLOCKS = 128;
    private static final int DEFAULT_MAX_ENTRY_POINTS = 128;
    private static final int HARD_MAX_ITEMS = 512;

    public ProgramIntelligenceToolProvider(McpSyncServer server) {
        super(server);
    }

    @Override
    public void registerTools() {
        registerProgramOverviewTool();
    }

    private void registerProgramOverviewTool() {
        Map<String, Object> properties = new LinkedHashMap<>();
        properties.put("programPath",
            SchemaUtil.stringProperty("Path in the Ghidra Project to the program"));
        properties.put("maxBlocks", SchemaUtil.integerPropertyWithDefault(
            "Maximum memory blocks to return (hard cap 512)", DEFAULT_MAX_BLOCKS));
        properties.put("maxEntryPoints", SchemaUtil.integerPropertyWithDefault(
            "Maximum entry points to return (hard cap 512)", DEFAULT_MAX_ENTRY_POINTS));

        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("get-program-overview")
            .title("Get Program Overview")
            .description("Get a compact, read-only, format-neutral overview of a program: " +
                "format, architecture, compiler metadata, image bounds, hashes, memory blocks, " +
                "entry points, relocation/source-map counts, and analysis counts. Use this for " +
                "initial binary triage instead of manually reconstructing headers from bytes.")
            .inputSchema(createSchema(properties, List.of("programPath")))
            .build();

        registerTool(tool, (exchange, request) -> {
            Program program = getProgramFromArgs(request);
            int maxBlocks = boundedPositive(
                getOptionalInt(request, "maxBlocks", DEFAULT_MAX_BLOCKS), "maxBlocks");
            int maxEntryPoints = boundedPositive(
                getOptionalInt(request, "maxEntryPoints", DEFAULT_MAX_ENTRY_POINTS), "maxEntryPoints");

            Map<String, Object> result = new LinkedHashMap<>();
            result.put("programPath", program.getDomainFile().getPathname());
            result.put("name", program.getName());
            putIfPresent(result, "executableFormat", program.getExecutableFormat());
            putIfPresent(result, "executablePath", program.getExecutablePath());
            putIfPresent(result, "md5", program.getExecutableMD5());
            putIfPresent(result, "sha256", program.getExecutableSHA256());

            result.put("language", program.getLanguageID().getIdAsString());
            result.put("compilerSpec",
                program.getCompilerSpec().getCompilerSpecID().getIdAsString());
            result.put("compiler", program.getCompiler());
            result.put("pointerSize", program.getDefaultPointerSize());

            Address imageBase = program.getImageBase();
            AddressSpace defaultSpace = program.getAddressFactory().getDefaultAddressSpace();
            result.put("defaultAddressSpace", defaultSpace.getName());
            if (imageBase != null) {
                result.put("imageBase", AddressUtil.formatAddress(imageBase));
                result.put("imageBaseAddressSpace", imageBase.getAddressSpace().getName());
            }

            // Program.getMinAddress()/getMaxAddress() may select an address from a
            // different memory space based on Ghidra's cross-space ordering. That
            // makes a bare numeric "maxAddress" misleading for formats that also
            // create non-loaded/file/external spaces. Report bounds for the default
            // memory space explicitly instead.
            MemoryBlock[] blocks = program.getMemory().getBlocks();
            Address minAddress = null;
            Address maxAddress = null;
            for (MemoryBlock block : blocks) {
                Address start = block.getStart();
                Address end = block.getEnd();
                if (!start.getAddressSpace().equals(defaultSpace)) {
                    continue;
                }
                if (minAddress == null || start.compareTo(minAddress) < 0) {
                    minAddress = start;
                }
                if (maxAddress == null || end.compareTo(maxAddress) > 0) {
                    maxAddress = end;
                }
            }
            result.put("addressBoundsScope", "default-memory-space");
            if (minAddress != null) {
                result.put("minAddress", AddressUtil.formatAddress(minAddress));
            }
            if (maxAddress != null) {
                result.put("maxAddress", AddressUtil.formatAddress(maxAddress));
            }

            result.put("functionCount", program.getFunctionManager().getFunctionCount());
            result.put("symbolCount", program.getSymbolTable().getNumSymbols());

            RelocationTable relocations = program.getRelocationTable();
            result.put("relocationCount", relocations.getSize());
            result.put("relocatable", relocations.isRelocatable());

            int sourceFileCount = program.getSourceFileManager().getAllSourceFiles().size();
            int mappedSourceFileCount = program.getSourceFileManager().getMappedSourceFiles().size();
            result.put("sourceFileCount", sourceFileCount);
            result.put("mappedSourceFileCount", mappedSourceFileCount);

            List<Map<String, Object>> blockData = new ArrayList<>();
            int returnedBlocks = Math.min(blocks.length, maxBlocks);
            for (int i = 0; i < returnedBlocks; i++) {
                MemoryBlock block = blocks[i];
                Map<String, Object> info = new LinkedHashMap<>();
                info.put("name", block.getName());
                info.put("addressSpace", block.getStart().getAddressSpace().getName());
                info.put("start", AddressUtil.formatAddress(block.getStart()));
                info.put("end", AddressUtil.formatAddress(block.getEnd()));
                info.put("size", block.getSize());
                info.put("readable", block.isRead());
                info.put("writable", block.isWrite());
                info.put("executable", block.isExecute());
                info.put("initialized", block.isInitialized());
                info.put("mapped", block.isMapped());
                info.put("overlay", block.isOverlay());
                blockData.add(info);
            }
            result.put("memoryBlockCount", blocks.length);
            result.put("memoryBlocks", blockData);
            result.put("memoryBlocksTruncated", blocks.length > returnedBlocks);

            SymbolTable symbols = program.getSymbolTable();
            AddressIterator entryIterator = symbols.getExternalEntryPointIterator();
            List<Map<String, Object>> entryPoints = new ArrayList<>();
            int totalEntryPoints = 0;
            while (entryIterator.hasNext()) {
                Address address = entryIterator.next();
                totalEntryPoints++;
                if (entryPoints.size() >= maxEntryPoints) {
                    continue;
                }

                Map<String, Object> entry = new LinkedHashMap<>();
                entry.put("address", AddressUtil.formatAddress(address));
                Symbol symbol = symbols.getPrimarySymbol(address);
                if (symbol != null) {
                    entry.put("symbol", symbol.getName());
                }
                Function function = program.getFunctionManager().getFunctionAt(address);
                if (function != null) {
                    entry.put("function", function.getName());
                }
                entryPoints.add(entry);
            }
            result.put("entryPointCount", totalEntryPoints);
            result.put("entryPoints", entryPoints);
            result.put("entryPointsTruncated", totalEntryPoints > entryPoints.size());

            return createJsonResult(result);
        });
    }

    private static int boundedPositive(int value, String name) {
        if (value <= 0) {
            throw new IllegalArgumentException(name + " must be greater than zero");
        }
        return Math.min(value, HARD_MAX_ITEMS);
    }

    private static void putIfPresent(Map<String, Object> target, String key, String value) {
        if (value != null && !value.isBlank()) {
            target.put(key, value);
        }
    }
}
