"""
Test schemas based on OpenAI Structured Output documentation.
Source: https://platform.openai.com/docs/guides/structured-outputs#supported-schemas
"""

# Example 1: User data with pattern and format validation (lines 52-78)
USER_DATA_SCHEMA = {
    "type": "object",
    "properties": {
        "name": {
            "type": "string",
            "description": "The name of the user"
        },
        "username": {
            "type": "string",
            "description": "The username of the user. Must start with @",
            "pattern": "^@[a-zA-Z0-9_]+$"
        },
        "email": {
            "type": "string",
            "description": "The email of the user",
            "format": "email"
        }
    },
    "additionalProperties": False,
    "required": ["name", "username", "email"]
}

# Example 2: Weather API with enum (lines 103-123)
WEATHER_SCHEMA = {
    "type": "object",
    "properties": {
        "location": {
            "type": "string",
            "description": "The location to get the weather for"
        },
        "unit": {
            "type": "string",
            "description": "The unit to return the temperature in",
            "enum": ["F", "C"]
        }
    },
    "additionalProperties": False,
    "required": ["location", "unit"]
}

# Example 3: Optional field using union type (lines 127-149)
WEATHER_OPTIONAL_SCHEMA = {
    "type": "object",
    "properties": {
        "location": {
            "type": "string",
            "description": "The location to get the weather for"
        },
        "unit": {
            "type": ["string", "null"],
            "description": "The unit to return the temperature in",
            "enum": ["F", "C", None]
        }
    },
    "additionalProperties": False,
    "required": ["location", "unit"]
}

# Example 4: anyOf with user/address objects (lines 211-266)
ANYOF_USER_ADDRESS_SCHEMA = {
    "type": "object",
    "properties": {
        "item": {
            "anyOf": [
                {
                    "type": "object",
                    "description": "The user object to insert into the database",
                    "properties": {
                        "name": {
                            "type": "string",
                            "description": "The name of the user"
                        },
                        "age": {
                            "type": "number",
                            "description": "The age of the user"
                        }
                    },
                    "additionalProperties": False,
                    "required": ["name", "age"]
                },
                {
                    "type": "object",
                    "description": "The address object to insert into the database",
                    "properties": {
                        "number": {
                            "type": "string",
                            "description": "The number of the address. Eg. for 123 main st, this would be 123"
                        },
                        "street": {
                            "type": "string",
                            "description": "The street name. Eg. for 123 main st, this would be main st"
                        },
                        "city": {
                            "type": "string",
                            "description": "The city of the address"
                        }
                    },
                    "additionalProperties": False,
                    "required": ["number", "street", "city"]
                }
            ]
        }
    },
    "additionalProperties": False,
    "required": ["item"]
}

# Example 5: Schema with definitions (lines 272-308)
DEFINITIONS_SCHEMA = {
    "type": "object",
    "properties": {
        "steps": {
            "type": "array",
            "items": {
                "$ref": "#/$defs/step"
            }
        },
        "final_answer": {
            "type": "string"
        }
    },
    "$defs": {
        "step": {
            "type": "object",
            "properties": {
                "explanation": {
                    "type": "string"
                },
                "output": {
                    "type": "string"
                }
            },
            "required": ["explanation", "output"],
            "additionalProperties": False
        }
    },
    "required": ["steps", "final_answer"],
    "additionalProperties": False
}

# Example 6: Recursive UI schema (lines 314-360)
RECURSIVE_UI_SCHEMA = {
    "type": "object",
    "properties": {
        "type": {
            "type": "string",
            "description": "The type of the UI component",
            "enum": ["div", "button", "header", "section", "field", "form"]
        },
        "label": {
            "type": "string",
            "description": "The label of the UI component, used for buttons or form fields"
        },
        "children": {
            "type": "array",
            "description": "Nested UI components",
            "items": {
                "$ref": "#"
            }
        },
        "attributes": {
            "type": "array",
            "description": "Arbitrary attributes for the UI component, suitable for any element",
            "items": {
                "type": "object",
                "properties": {
                    "name": {
                        "type": "string",
                        "description": "The name of the attribute, for example onClick or className"
                    },
                    "value": {
                        "type": "string",
                        "description": "The value of the attribute"
                    }
                },
                "additionalProperties": False,
                "required": ["name", "value"]
            }
        }
    },
    "required": ["type", "label", "children", "attributes"],
    "additionalProperties": False
}

# Example 7: Recursive linked list schema (lines 364-400)
RECURSIVE_LINKED_LIST_SCHEMA = {
    "type": "object",
    "properties": {
        "linked_list": {
            "$ref": "#/$defs/linked_list_node"
        }
    },
    "$defs": {
        "linked_list_node": {
            "type": "object",
            "properties": {
                "value": {
                    "type": "number"
                },
                "next": {
                    "anyOf": [
                        {
                            "$ref": "#/$defs/linked_list_node"
                        },
                        {
                            "type": "null"
                        }
                    ]
                }
            },
            "additionalProperties": False,
            "required": ["next", "value"]
        }
    },
    "additionalProperties": False,
    "required": ["linked_list"]
}

# Additional test schemas for comprehensive coverage

# Simple array of primitives
SIMPLE_ARRAY_SCHEMA = {
    "type": "object",
    "properties": {
        "tags": {
            "type": "array",
            "items": {
                "type": "string"
            },
            "minItems": 1,
            "maxItems": 10
        }
    },
    "required": ["tags"],
    "additionalProperties": False
}

# Nested objects without $ref
NESTED_OBJECT_SCHEMA = {
    "type": "object",
    "properties": {
        "user": {
            "type": "object",
            "properties": {
                "name": {
                    "type": "string"
                },
                "address": {
                    "type": "object",
                    "properties": {
                        "street": {
                            "type": "string"
                        },
                        "city": {
                            "type": "string"
                        }
                    },
                    "required": ["street", "city"],
                    "additionalProperties": False
                }
            },
            "required": ["name", "address"],
            "additionalProperties": False
        }
    },
    "required": ["user"],
    "additionalProperties": False
}

# Number constraints
NUMBER_CONSTRAINTS_SCHEMA = {
    "type": "object",
    "properties": {
        "age": {
            "type": "integer",
            "minimum": 0,
            "maximum": 150
        },
        "price": {
            "type": "number",
            "exclusiveMinimum": 0,
            "multipleOf": 0.01
        }
    },
    "required": ["age", "price"],
    "additionalProperties": False
}

# String format validation
STRING_FORMAT_SCHEMA = {
    "type": "object",
    "properties": {
        "email": {
            "type": "string",
            "format": "email"
        },
        "uuid": {
            "type": "string",
            "format": "uuid"
        },
        "date": {
            "type": "string",
            "format": "date"
        },
        "datetime": {
            "type": "string",
            "format": "date-time"
        }
    },
    "required": ["email", "uuid", "date", "datetime"],
    "additionalProperties": False
}

# Multiple enums
MULTIPLE_ENUMS_SCHEMA = {
    "type": "object",
    "properties": {
        "status": {
            "type": "string",
            "enum": ["pending", "approved", "rejected"]
        },
        "priority": {
            "type": "string",
            "enum": ["low", "medium", "high", "critical"]
        }
    },
    "required": ["status", "priority"],
    "additionalProperties": False
}

# Array of objects
ARRAY_OF_OBJECTS_SCHEMA = {
    "type": "object",
    "properties": {
        "items": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "id": {
                        "type": "integer"
                    },
                    "name": {
                        "type": "string"
                    }
                },
                "required": ["id", "name"],
                "additionalProperties": False
            },
            "minItems": 1
        }
    },
    "required": ["items"],
    "additionalProperties": False
}

# All schemas for easy access
ALL_SCHEMAS = {
    "USER_DATA_SCHEMA": USER_DATA_SCHEMA,
    "WEATHER_SCHEMA": WEATHER_SCHEMA,
    "WEATHER_OPTIONAL_SCHEMA": WEATHER_OPTIONAL_SCHEMA,
    "ANYOF_USER_ADDRESS_SCHEMA": ANYOF_USER_ADDRESS_SCHEMA,
    "DEFINITIONS_SCHEMA": DEFINITIONS_SCHEMA,
    "RECURSIVE_UI_SCHEMA": RECURSIVE_UI_SCHEMA,
    "RECURSIVE_LINKED_LIST_SCHEMA": RECURSIVE_LINKED_LIST_SCHEMA,
    "SIMPLE_ARRAY_SCHEMA": SIMPLE_ARRAY_SCHEMA,
    "NESTED_OBJECT_SCHEMA": NESTED_OBJECT_SCHEMA,
    "NUMBER_CONSTRAINTS_SCHEMA": NUMBER_CONSTRAINTS_SCHEMA,
    "STRING_FORMAT_SCHEMA": STRING_FORMAT_SCHEMA,
    "MULTIPLE_ENUMS_SCHEMA": MULTIPLE_ENUMS_SCHEMA,
    "ARRAY_OF_OBJECTS_SCHEMA": ARRAY_OF_OBJECTS_SCHEMA,
}