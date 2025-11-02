package com.themixednuts.tools;

import com.themixednuts.annotation.GhidraMcpTool;
import com.themixednuts.exceptions.GhidraMcpException;
import com.themixednuts.models.GhidraMcpError;
import com.themixednuts.models.OperationResult;
import com.themixednuts.utils.jsonschema.JsonSchema;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder;
import com.themixednuts.utils.jsonschema.JsonSchemaBuilder.IObjectSchemaBuilder;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.FunctionTag;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolType;
import io.modelcontextprotocol.common.McpTransportContext;
import reactor.core.publisher.Mono;

import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

@GhidraMcpTool(
    name = "Manage Function Tags",
    description = "Function tag CRUD operations: add, list, and remove tags from functions.",
    mcpName = "manage_function_tags",
    mcpDescription = """
    <use_case>
    Tag management for organizing and categorizing functions in reverse engineering workflows.
    Add descriptive tags to functions, list existing tags, or remove tags. Tags are simple
    string identifiers that help organize analysis results and improve code navigation.
    </use_case>

    <important_notes>
    - Tags are automatically created when first added to a function
    - Multiple tags can be added to a single function
    - Supports function identification by name, address, or symbol ID
    - The 'list' action returns all tags for a specific function
    - Use ManageFunctionsTool for other function operations
    - Use ListFunctionsTool for browsing functions
    </important_notes>

    <examples>
    Add a tag to a function by name:
    {
      "fileName": "program.exe",
      "action": "add",
      "function_name": "main",
      "tags": ["entry_point"]
    }

    Add multiple tags to a function:
    {
      "fileName": "program.exe",
      "action": "add",
      "address": "0x401000",
      "tags": ["crypto", "important"]
    }

    List all tags for a function:
    {
      "fileName": "program.exe",
      "action": "list",
      "function_name": "decrypt_data"
    }

    Remove a tag from a function:
    {
      "fileName": "program.exe",
      "action": "remove",
      "address": "0x401000",
      "tags": ["temp"]
    }
    </examples>
    """
)
public class ManageTagsTool implements IGhidraMcpSpecification {

    public static final String ARG_ACTION = "action";
    public static final String ARG_FUNCTION_NAME = "function_name";
    public static final String ARG_TAGS = "tags";

    private static final String ACTION_ADD = "add";
    private static final String ACTION_LIST = "list";
    private static final String ACTION_REMOVE = "remove";

    /**
     * Defines the JSON input schema for tag management operations.
     *
     * @return The JsonSchema defining the expected input arguments
     */
    @Override
    public JsonSchema schema() {
        IObjectSchemaBuilder schemaRoot = IGhidraMcpSpecification.createBaseSchemaNode();

        schemaRoot.property(ARG_FILE_NAME,
                JsonSchemaBuilder.string(mapper)
                        .description("The name of the program file."));

        schemaRoot.property(ARG_ACTION, JsonSchemaBuilder.string(mapper)
                .enumValues(ACTION_ADD, ACTION_LIST, ACTION_REMOVE)
                .description("Action to perform: add tags, list tags, or remove tags"));

        schemaRoot.property(ARG_SYMBOL_ID, JsonSchemaBuilder.integer(mapper)
                .description("Symbol ID to identify target function (highest precedence)"));

        schemaRoot.property(ARG_ADDRESS, JsonSchemaBuilder.string(mapper)
                .description("Function address to identify target function")
                .pattern("^(0x)?[0-9a-fA-F]+$"));

        schemaRoot.property(ARG_FUNCTION_NAME, JsonSchemaBuilder.string(mapper)
                .description("Function name to identify target function"));

        schemaRoot.property(ARG_TAGS, JsonSchemaBuilder.array(mapper)
                .items(JsonSchemaBuilder.string(mapper))
                .description("Tag name(s) to add or remove as an array of strings."));

        schemaRoot.requiredProperty(ARG_FILE_NAME)
                .requiredProperty(ARG_ACTION);

        return schemaRoot.build();
    }

    /**
     * Executes the tag management operation.
     *
     * @param context The MCP transport context
     * @param args The tool arguments containing fileName, action, and action-specific parameters
     * @param tool The Ghidra PluginTool context
     * @return A Mono emitting the result of the tag operation
     */
    @Override
    public Mono<? extends Object> execute(McpTransportContext context, Map<String, Object> args, PluginTool tool) {
        GhidraMcpTool annotation = this.getClass().getAnnotation(GhidraMcpTool.class);

        return getProgram(args, tool).flatMap(program -> {
            String action = getRequiredStringArgument(args, ARG_ACTION);

            return switch (action.toLowerCase(Locale.ROOT)) {
                case ACTION_ADD -> handleAdd(program, args, annotation);
                case ACTION_LIST -> handleList(program, args, annotation);
                case ACTION_REMOVE -> handleRemove(program, args, annotation);
                default -> {
                    GhidraMcpError error = GhidraMcpError.validation()
                        .errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
                        .message("Invalid action: " + action)
                        .context(new GhidraMcpError.ErrorContext(
                            annotation.mcpName(),
                            "action validation",
                            args,
                            Map.of(ARG_ACTION, action),
                            Map.of("validActions", List.of(ACTION_ADD, ACTION_LIST, ACTION_REMOVE))))
                        .suggestions(List.of(
                            new GhidraMcpError.ErrorSuggestion(
                                GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
                                "Use a valid action",
                                "Choose from: add, list, remove",
                                List.of(ACTION_ADD, ACTION_LIST, ACTION_REMOVE),
                                null)))
                        .build();
                    yield Mono.error(new GhidraMcpException(error));
                }
            };
        });
    }

    /**
     * Handles adding tags to a function.
     */
    private Mono<? extends Object> handleAdd(Program program, Map<String, Object> args, GhidraMcpTool annotation) {
        String toolOperation = annotation.mcpName() + ".add";
        List<String> tagNames = getTagsFromArgs(args);

        return resolveFunction(program, args, annotation, toolOperation)
            .flatMap(function -> executeInTransaction(program, "MCP - Add Tag(s) to " + function.getName(), () -> {
                List<String> addedTags = new ArrayList<>();
                List<String> existingTags = new ArrayList<>();
                List<String> failedTags = new ArrayList<>();

                for (String tagName : tagNames) {
                    String trimmedTag = tagName.trim();
                    if (trimmedTag.isEmpty()) {
                        continue;
                    }

                    // Validate tag name
                    String validationError = validateTagName(trimmedTag);
                    if (validationError != null) {
                        failedTags.add(trimmedTag + " (" + validationError + ")");
                        continue;
                    }

                    // Check if tag already exists on function
                    boolean tagExists = function.getTags().stream()
                        .anyMatch(tag -> tag.getName().equals(trimmedTag));

                    if (tagExists) {
                        existingTags.add(trimmedTag);
                    } else {
                        // addTag creates the tag if it doesn't exist
                        boolean success = function.addTag(trimmedTag);
                        if (success) {
                            addedTags.add(trimmedTag);
                        } else {
                            failedTags.add(trimmedTag + " (failed to add)");
                        }
                    }
                }

                Map<String, Object> metadata = new LinkedHashMap<>();
                metadata.put("function_name", function.getName());
                metadata.put("function_address", function.getEntryPoint().toString());
                metadata.put("added_tags", addedTags);
                if (!existingTags.isEmpty()) {
                    metadata.put("already_existing_tags", existingTags);
                }
                if (!failedTags.isEmpty()) {
                    metadata.put("failed_tags", failedTags);
                }

                // Get all current tags
                Set<FunctionTag> allTags = function.getTags();
                metadata.put("all_tags", allTags.stream()
                    .map(FunctionTag::getName)
                    .sorted()
                    .collect(Collectors.toList()));

                String message = addedTags.isEmpty()
                    ? "All specified tags already exist on function"
                    : "Added " + addedTags.size() + " tag(s) to function";

                return OperationResult
                    .success("add_tags", function.getEntryPoint().toString(), message)
                    .setMetadata(metadata);
            }));
    }

    /**
     * Handles listing tags for a function.
     */
    private Mono<? extends Object> handleList(Program program, Map<String, Object> args, GhidraMcpTool annotation) {
        String toolOperation = annotation.mcpName() + ".list";

        return resolveFunction(program, args, annotation, toolOperation)
            .flatMap(function -> Mono.fromCallable(() -> {
                Set<FunctionTag> tags = function.getTags();

                List<Map<String, String>> tagList = tags.stream()
                    .map(tag -> {
                        Map<String, String> tagInfo = new LinkedHashMap<>();
                        tagInfo.put("name", tag.getName());
                        String comment = tag.getComment();
                        if (comment != null && !comment.isEmpty()) {
                            tagInfo.put("comment", comment);
                        }
                        return tagInfo;
                    })
                    .sorted(Comparator.comparing(m -> m.get("name")))
                    .collect(Collectors.toList());

                Map<String, Object> result = new LinkedHashMap<>();
                result.put("function_name", function.getName());
                result.put("function_address", function.getEntryPoint().toString());
                result.put("tag_count", tags.size());
                result.put("tags", tagList);

                return result;
            }));
    }

    /**
     * Handles removing tags from a function.
     */
    private Mono<? extends Object> handleRemove(Program program, Map<String, Object> args, GhidraMcpTool annotation) {
        String toolOperation = annotation.mcpName() + ".remove";
        List<String> tagNames = getTagsFromArgs(args);

        return resolveFunction(program, args, annotation, toolOperation)
            .flatMap(function -> executeInTransaction(program, "MCP - Remove Tag(s) from " + function.getName(), () -> {
                List<String> removedTags = new ArrayList<>();
                List<String> notFoundTags = new ArrayList<>();

                for (String tagName : tagNames) {
                    String trimmedTag = tagName.trim();
                    if (trimmedTag.isEmpty()) {
                        continue;
                    }

                    // Check if tag exists on function
                    boolean tagExists = function.getTags().stream()
                        .anyMatch(tag -> tag.getName().equals(trimmedTag));

                    if (tagExists) {
                        function.removeTag(trimmedTag);
                        removedTags.add(trimmedTag);
                    } else {
                        notFoundTags.add(trimmedTag);
                    }
                }

                Map<String, Object> metadata = new LinkedHashMap<>();
                metadata.put("function_name", function.getName());
                metadata.put("function_address", function.getEntryPoint().toString());
                metadata.put("removed_tags", removedTags);
                if (!notFoundTags.isEmpty()) {
                    metadata.put("tags_not_found", notFoundTags);
                }

                // Get remaining tags
                Set<FunctionTag> remainingTags = function.getTags();
                metadata.put("remaining_tags", remainingTags.stream()
                    .map(FunctionTag::getName)
                    .sorted()
                    .collect(Collectors.toList()));

                String message = removedTags.isEmpty()
                    ? "No matching tags found on function"
                    : "Removed " + removedTags.size() + " tag(s) from function";

                return OperationResult
                    .success("remove_tags", function.getEntryPoint().toString(), message)
                    .setMetadata(metadata);
            }));
    }

    /**
     * Extracts tags from the args map, handling both List and single string values.
     */
    @SuppressWarnings("unchecked")
    private List<String> getTagsFromArgs(Map<String, Object> args) {
        Object tagsObj = args.get(ARG_TAGS);
        if (tagsObj == null) {
            throw new IllegalArgumentException("Missing required argument 'tags'");
        }

        if (tagsObj instanceof List) {
            List<?> rawList = (List<?>) tagsObj;
            List<String> tags = new ArrayList<>();
            for (Object item : rawList) {
                if (item instanceof String) {
                    tags.add((String) item);
                } else {
                    throw new IllegalArgumentException("All items in 'tags' array must be strings");
                }
            }
            return tags;
        } else {
            throw new IllegalArgumentException("Argument 'tags' must be an array of strings");
        }
    }

    /**
     * Resolves a function using symbol_id, address, or function_name (in order of precedence).
     */
    private Mono<Function> resolveFunction(Program program, Map<String, Object> args,
                                          GhidraMcpTool annotation, String toolOperation) {
        return Mono.fromCallable(() -> {
            FunctionManager functionManager = program.getFunctionManager();

            // Apply precedence: symbol_id > address > function_name
            if (args.containsKey(ARG_SYMBOL_ID)) {
                Long symbolId = getOptionalLongArgument(args, ARG_SYMBOL_ID).orElse(null);
                if (symbolId != null) {
                    Symbol symbol = program.getSymbolTable().getSymbol(symbolId);
                    if (symbol != null && symbol.getSymbolType() == SymbolType.FUNCTION) {
                        Function function = functionManager.getFunctionAt(symbol.getAddress());
                        if (function != null) {
                            return function;
                        }
                    }
                }
                throw new GhidraMcpException(createFunctionNotFoundError(toolOperation, "symbol_id", symbolId.toString()));
            } else if (args.containsKey(ARG_ADDRESS)) {
                String address = getOptionalStringArgument(args, ARG_ADDRESS).orElse(null);
                if (address != null && !address.trim().isEmpty()) {
                    try {
                        Address functionAddress = program.getAddressFactory().getAddress(address);
                        if (functionAddress != null) {
                            Function function = functionManager.getFunctionAt(functionAddress);
                            if (function != null) {
                                return function;
                            }
                        }
                    } catch (Exception e) {
                        throw new GhidraMcpException(createInvalidAddressError(address, e));
                    }
                }
                throw new GhidraMcpException(createFunctionNotFoundError(toolOperation, "address", address));
            } else if (args.containsKey(ARG_FUNCTION_NAME)) {
                String name = getOptionalStringArgument(args, ARG_FUNCTION_NAME).orElse(null);
                if (name != null && !name.trim().isEmpty()) {
                    // First try exact match
                    Optional<Function> exactMatch = StreamSupport.stream(functionManager.getFunctions(true).spliterator(), false)
                        .filter(f -> f.getName().equals(name))
                        .findFirst();

                    if (exactMatch.isPresent()) {
                        return exactMatch.get();
                    }

                    // Then try regex match
                    try {
                        List<Function> regexMatches = StreamSupport.stream(functionManager.getFunctions(true).spliterator(), false)
                            .filter(f -> f.getName().matches(name))
                            .collect(Collectors.toList());

                        if (regexMatches.size() == 1) {
                            return regexMatches.get(0);
                        } else if (regexMatches.size() > 1) {
                            throw new GhidraMcpException(createMultipleFunctionsFoundError(toolOperation, name, regexMatches));
                        }
                    } catch (Exception e) {
                        throw new GhidraMcpException(createInvalidRegexError(name, e));
                    }
                }
                throw new GhidraMcpException(createFunctionNotFoundError(toolOperation, "function_name", name));
            } else {
                throw new GhidraMcpException(createMissingParameterError(toolOperation));
            }
        });
    }

    private GhidraMcpError createFunctionNotFoundError(String toolOperation, String searchType, String searchValue) {
        return GhidraMcpError.validation()
            .errorCode(GhidraMcpError.ErrorCode.FUNCTION_NOT_FOUND)
            .message("Function not found using " + searchType + ": " + searchValue)
            .context(new GhidraMcpError.ErrorContext(
                toolOperation,
                "function resolution",
                Map.of(searchType, searchValue),
                Map.of(),
                Map.of("searchMethod", searchType)))
            .suggestions(List.of(
                new GhidraMcpError.ErrorSuggestion(
                    GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
                    "Verify the function exists",
                    "Check that the function identifier is correct",
                    List.of(
                        "\"symbol_id\": 12345",
                        "\"address\": \"0x401000\"",
                        "\"function_name\": \"main\""),
                    null)))
            .build();
    }

    private GhidraMcpError createMultipleFunctionsFoundError(String toolOperation, String searchValue, List<Function> functions) {
        List<String> functionNames = functions.stream()
            .map(Function::getName)
            .limit(5)
            .collect(Collectors.toList());

        return GhidraMcpError.validation()
            .errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
            .message("Multiple functions found for name pattern: " + searchValue)
            .context(new GhidraMcpError.ErrorContext(
                toolOperation,
                "function resolution",
                Map.of("function_name", searchValue),
                Map.of("matchCount", functions.size()),
                Map.of("firstFiveMatches", functionNames)))
            .suggestions(List.of(
                new GhidraMcpError.ErrorSuggestion(
                    GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
                    "Use a more specific function identifier",
                    "Consider using symbol_id or address for exact identification",
                    List.of(
                        "\"symbol_id\": 12345",
                        "\"address\": \"0x401000\"",
                        "\"function_name\": \"exact_function_name\""),
                    null)))
            .build();
    }

    private GhidraMcpError createInvalidAddressError(String addressStr, Exception cause) {
        return GhidraMcpError.validation()
            .errorCode(GhidraMcpError.ErrorCode.ADDRESS_PARSE_FAILED)
            .message("Invalid address format: " + addressStr)
            .context(new GhidraMcpError.ErrorContext(
                this.getClass().getAnnotation(GhidraMcpTool.class).mcpName(),
                "address parsing",
                Map.of(ARG_ADDRESS, addressStr),
                Map.of(),
                Map.of("parseError", cause.getMessage())))
            .suggestions(List.of(
                new GhidraMcpError.ErrorSuggestion(
                    GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
                    "Use valid hexadecimal address format",
                    "Provide address in proper format",
                    List.of("0x401000", "401000", "0x00401000"),
                    null)))
            .build();
    }

    private GhidraMcpError createInvalidRegexError(String pattern, Exception cause) {
        return GhidraMcpError.validation()
            .errorCode(GhidraMcpError.ErrorCode.INVALID_ARGUMENT_VALUE)
            .message("Invalid regex pattern: " + cause.getMessage())
            .context(new GhidraMcpError.ErrorContext(
                this.getClass().getAnnotation(GhidraMcpTool.class).mcpName(),
                "regex compilation",
                Map.of(ARG_FUNCTION_NAME, pattern),
                Map.of(),
                Map.of("regexError", cause.getMessage())))
            .suggestions(List.of(
                new GhidraMcpError.ErrorSuggestion(
                    GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
                    "Provide a valid Java regex pattern",
                    "Use proper regex syntax for pattern matching",
                    List.of(".*main.*", "decrypt_.*", "^get.*"),
                    null)))
            .build();
    }

    private GhidraMcpError createMissingParameterError(String toolOperation) {
        return GhidraMcpError.validation()
            .errorCode(GhidraMcpError.ErrorCode.MISSING_REQUIRED_ARGUMENT)
            .message("No function identifier provided")
            .context(new GhidraMcpError.ErrorContext(
                toolOperation,
                "parameter validation",
                Map.of(),
                Map.of(),
                Map.of("availableParameters", List.of(ARG_SYMBOL_ID, ARG_ADDRESS, ARG_FUNCTION_NAME))))
            .suggestions(List.of(
                new GhidraMcpError.ErrorSuggestion(
                    GhidraMcpError.ErrorSuggestion.SuggestionType.FIX_REQUEST,
                    "Provide a function identifier",
                    "Use symbol_id, address, or function_name parameter",
                    List.of(
                        "\"symbol_id\": 12345",
                        "\"address\": \"0x401000\"",
                        "\"function_name\": \"main\""),
                    null)))
            .build();
    }

    /**
     * Validates a tag name for basic constraints.
     *
     * @param tagName The tag name to validate (should already be trimmed)
     * @return null if valid, or an error message if invalid
     */
    private String validateTagName(String tagName) {
        // Check for empty tag
        if (tagName == null || tagName.isEmpty()) {
            return "tag name is empty";
        }

        // Check for excessive length (Ghidra may have internal limits)
        // Using a conservative limit of 100 characters
        if (tagName.length() > 100) {
            return "tag name too long (max 100 characters)";
        }

        // Check for whitespace-only tag
        if (tagName.trim().isEmpty()) {
            return "tag name contains only whitespace";
        }

        // Check for problematic characters that might cause issues
        // Ghidra tags generally support alphanumeric and common symbols
        // but we should avoid control characters and some special chars
        if (tagName.contains("\n") || tagName.contains("\r") || tagName.contains("\t")) {
            return "tag name contains control characters";
        }

        return null;
    }
}
