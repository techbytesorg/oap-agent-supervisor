from pydantic import create_model, Field as PydanticField, constr, conint, confloat
from typing import Any, Dict, List, Union, Optional, Literal, get_args, Type, ForwardRef
from enum import Enum as PyEnum
import logging
import re

logger = logging.getLogger(__name__)


def _resolve_ref(ref: str, defs: Dict[str, Any], model_cache: Dict[str, Type]) -> Type:
    """
    Resolve a $ref to its schema definition.

    Args:
        ref: The reference string (e.g., "#/$defs/step" or "#")
        defs: The $defs dictionary from the schema
        model_cache: Cache of already created models to handle recursion

    Returns:
        The resolved type or forward reference string
    """
    if ref == "#":
        # Self-reference (root recursion)
        raise ValueError("Root recursion (#) must be handled by caller")

    if ref.startswith("#/$defs/"):
        def_name = ref.split("/")[-1]

        # Check if model is in cache
        if def_name in model_cache:
            cached = model_cache[def_name]
            # If None, it means the model is currently being built (recursive reference)
            if cached is None:
                # Return forward reference string
                return def_name
            return cached

        if def_name not in defs:
            raise ValueError(f"Definition '{def_name}' not found in $defs")

        # Create the model from the definition
        return _schema_to_type(defs[def_name], def_name, defs, model_cache)

    raise ValueError(f"Unsupported $ref format: {ref}")


def _handle_anyof(anyof_schemas: List[Dict[str, Any]], base_name: str, defs: Dict[str, Any], model_cache: Dict[str, Type]) -> Type:
    """
    Handle anyOf by creating a Union type.

    Args:
        anyof_schemas: List of schema options
        base_name: Base name for generated types
        defs: The $defs dictionary
        model_cache: Cache of already created models

    Returns:
        Union type of all options or forward reference string for recursion
    """
    types = []
    has_forward_ref = False

    for i, schema in enumerate(anyof_schemas):
        schema_type = schema.get("type")

        # Handle null type
        if schema_type == "null":
            types.append(type(None))
            continue

        # Handle object types
        if schema_type == "object":
            model_name = f"{base_name}Option{i}"
            resolved = _schema_to_type(schema, model_name, defs, model_cache)
            if isinstance(resolved, str):
                has_forward_ref = True
            types.append(resolved)
        # Handle $ref
        elif "$ref" in schema:
            resolved = _resolve_ref(schema["$ref"], defs, model_cache)
            if isinstance(resolved, str):
                # Forward reference - return as string to be resolved later
                has_forward_ref = True
            types.append(resolved)
        else:
            # Primitive types
            resolved = _schema_to_type(schema, f"{base_name}_{i}", defs, model_cache)
            if isinstance(resolved, str):
                has_forward_ref = True
            types.append(resolved)

    if len(types) == 1:
        return types[0]

    # If we have forward references, convert strings to ForwardRef
    if has_forward_ref:
        resolved_types = []
        for t in types:
            if isinstance(t, str):
                # Convert string to ForwardRef
                resolved_types.append(ForwardRef(t))
            else:
                resolved_types.append(t)
        return Union[tuple(resolved_types)]

    return Union[tuple(types)]


def _create_enum_type(enum_values: List[Any], enum_name: str) -> Type:
    """
    Create a Literal type or Enum from enum values.

    Args:
        enum_values: List of allowed values
        enum_name: Name for the enum type

    Returns:
        Literal type with enum values
    """
    # Use Literal for enums
    return Literal[tuple(enum_values)]


def _get_string_constraints(field_info: Dict[str, Any]) -> Dict[str, Any]:
    """Extract string validation constraints."""
    constraints = {}

    if "pattern" in field_info:
        constraints["pattern"] = field_info["pattern"]

    if "format" in field_info:
        # Pydantic doesn't natively support all JSON Schema formats
        # but we can add pattern constraints for some
        fmt = field_info["format"]
        if fmt == "email":
            # Basic email pattern
            constraints["pattern"] = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
        elif fmt == "uuid":
            constraints["pattern"] = r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
        elif fmt == "date":
            constraints["pattern"] = r'^\d{4}-\d{2}-\d{2}$'
        elif fmt == "date-time":
            constraints["pattern"] = r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}'
        elif fmt == "time":
            constraints["pattern"] = r'^\d{2}:\d{2}:\d{2}$'
        elif fmt == "ipv4":
            constraints["pattern"] = r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$'

    if "minLength" in field_info:
        constraints["min_length"] = field_info["minLength"]

    if "maxLength" in field_info:
        constraints["max_length"] = field_info["maxLength"]

    return constraints


def _get_number_constraints(field_info: Dict[str, Any]) -> Dict[str, Any]:
    """Extract number validation constraints."""
    constraints = {}

    if "minimum" in field_info:
        constraints["ge"] = field_info["minimum"]

    if "maximum" in field_info:
        constraints["le"] = field_info["maximum"]

    if "exclusiveMinimum" in field_info:
        constraints["gt"] = field_info["exclusiveMinimum"]

    if "exclusiveMaximum" in field_info:
        constraints["lt"] = field_info["exclusiveMaximum"]

    if "multipleOf" in field_info:
        constraints["multiple_of"] = field_info["multipleOf"]

    return constraints


def _get_array_constraints(field_info: Dict[str, Any]) -> Dict[str, Any]:
    """Extract array validation constraints."""
    constraints = {}

    if "minItems" in field_info:
        constraints["min_length"] = field_info["minItems"]

    if "maxItems" in field_info:
        constraints["max_length"] = field_info["maxItems"]

    return constraints


def _schema_to_type(schema: Dict[str, Any], type_name: str, defs: Dict[str, Any], model_cache: Dict[str, Type]) -> Type:
    """
    Convert a JSON schema to a Python type.

    Args:
        schema: The JSON schema
        type_name: Name for the type
        defs: The $defs dictionary
        model_cache: Cache of already created models

    Returns:
        Python type corresponding to the schema
    """
    # Handle $ref
    if "$ref" in schema:
        ref = schema["$ref"]
        if ref == "#":
            # Root self-reference - return forward reference
            return type_name
        return _resolve_ref(ref, defs, model_cache)

    # Handle anyOf
    if "anyOf" in schema:
        return _handle_anyof(schema["anyOf"], type_name, defs, model_cache)

    # Handle enum
    if "enum" in schema:
        return _create_enum_type(schema["enum"], type_name)

    # Get type
    schema_type = schema.get("type")

    # Handle union types (type as array, e.g., ["string", "null"])
    if isinstance(schema_type, list):
        types = []
        for t in schema_type:
            if t == "null":
                types.append(type(None))
            elif t == "string":
                types.append(str)
            elif t == "integer":
                types.append(int)
            elif t == "number":
                types.append(float)
            elif t == "boolean":
                types.append(bool)
            elif t == "array":
                # This is complex - would need items info
                types.append(list)
            elif t == "object":
                types.append(dict)
        return Union[tuple(types)] if len(types) > 1 else types[0]

    # Handle object
    if schema_type == "object":
        # Check if this model is already in cache (for recursion)
        if type_name in model_cache:
            return model_cache[type_name]

        # Create placeholder for recursive references
        model_cache[type_name] = None

        properties = schema.get("properties", {})
        required_fields = schema.get("required", [])

        fields = {}
        for field_name, field_info in properties.items():
            is_required = field_name in required_fields

            # Get field type
            field_type = _schema_to_type(field_info, f"{type_name}_{field_name}", defs, model_cache)

            # Handle forward references for recursion
            if field_type == type_name:
                field_type = f"'{type_name}'"

            # Get description
            description = field_info.get("description", "")

            # Build Field kwargs
            field_kwargs = {"description": description}

            # Add array constraints if this is an array field
            if field_info.get("type") == "array":
                array_constraints = _get_array_constraints(field_info)
                field_kwargs.update(array_constraints)

            # Create field with constraints
            if is_required:
                default = ...
            else:
                default = None
                field_type = Optional[field_type]

            fields[field_name] = (field_type, PydanticField(default, **field_kwargs))

        # Create the model
        model = create_model(type_name, **fields)
        model_cache[type_name] = model

        return model

    # Handle array
    if schema_type == "array":
        items_schema = schema.get("items", {})
        item_type = _schema_to_type(items_schema, f"{type_name}Item", defs, model_cache)

        # Handle forward references
        if isinstance(item_type, str):
            return f"List[{item_type}]"

        # Note: Array constraints (minItems, maxItems) are applied via Field in the parent object
        # We just return the List type here
        return List[item_type]

    # Handle primitives with constraints
    if schema_type == "string":
        constraints = _get_string_constraints(schema)
        if constraints:
            # Use constr for constrained strings
            return constr(**constraints)
        return str
    elif schema_type == "integer":
        constraints = _get_number_constraints(schema)
        if constraints:
            # Use conint for constrained integers
            return conint(**constraints)
        return int
    elif schema_type == "number":
        constraints = _get_number_constraints(schema)
        if constraints:
            # Use confloat for constrained floats
            return confloat(**constraints)
        return float
    elif schema_type == "boolean":
        return bool
    elif schema_type == "null":
        return type(None)

    # Default to Any for unknown types
    logger.warning(f"Unknown schema type: {schema_type}, defaulting to Any")
    return Any


def create_pydantic_model_from_json_schema(schema_json: Dict[str, Any], model_name: str):
    """
    Create a Pydantic model from a JSON schema dictionary.

    Supports OpenAI Structured Output schema features:
    - All types: string, number, integer, boolean, object, array, enum, anyOf
    - Nested objects and arrays
    - Enums and union types
    - $ref and $defs
    - Recursive schemas
    - Validation constraints (pattern, format, min/max, etc.)

    Args:
        schema_json: The JSON schema dictionary
        model_name: Name for the generated Pydantic model

    Returns:
        Dynamically created Pydantic model class
    """
    # Extract $defs if present
    defs = schema_json.get("$defs", {})

    # Model cache for handling recursion and references
    model_cache: Dict[str, Type] = {}

    # Create the root model
    result = _schema_to_type(schema_json, model_name, defs, model_cache)

    # Rebuild all models to resolve forward references
    for model in model_cache.values():
        if model is not None and hasattr(model, 'model_rebuild'):
            try:
                model.model_rebuild()
            except Exception as e:
                logger.debug(f"Failed to rebuild model: {e}")

    # If result is a model, return it
    if isinstance(result, type):
        return result

    # Otherwise wrap in a model
    return create_model(model_name, __root__=(result, ...))

async def load_schema_model(schema_name: str, user_id: str = None):
    """
    Load a schema model from the LangGraph memory store using get_store().

    Args:
        schema_name: Name of the schema to load
        user_id: User ID for namespace (optional, will try both user-specific and global)

    Returns:
        Pydantic model class for the requested schema

    Raises:
        ValueError: If schema is not found in memory store
    """
    from langgraph.config import get_store

    logger.debug(f"Loading schema model: {schema_name} for user: {user_id}")

    # Use LangGraph's get_store() to access the managed store
    store = get_store()
    logger.debug(f"Got store from get_store(): {type(store)}")

    # Try user-specific namespace first if user_id provided
    if user_id:
        try:
            namespace = (user_id, "schemas")
            logger.debug(f"Trying user-specific namespace: {namespace}")
            result = await store.aget(namespace, schema_name)
            if result:
                logger.debug(f"Found schema in user-specific namespace")
                schema_json = result.value
                return create_pydantic_model_from_json_schema(schema_json, schema_name)
            else:
                logger.debug(f"Schema not found in user-specific namespace")
        except Exception as e:
            logger.debug(f"Error accessing user-specific namespace: {e}")

    # Fallback to global namespace for backwards compatibility
    try:
        global_namespace = ("schemas",)
        logger.debug(f"Trying global namespace: {global_namespace}")
        result = await store.aget(global_namespace, schema_name)
        if result:
            schema_json = result.value
            logger.debug(f"Found schema in global namespace")
            return create_pydantic_model_from_json_schema(schema_json, schema_name)
    except Exception as e:
        logger.debug(f"Error accessing global namespace: {e}")

    logger.warning(f"Schema {schema_name} not found in any namespace")
    raise ValueError(f"Schema {schema_name} not found in memory store")