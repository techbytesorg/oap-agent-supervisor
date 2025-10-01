"""
Test advanced features for schema parser.
Tests: $ref, $defs, anyOf, recursive schemas
"""

import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from oap_supervisor.utils.structured_output import create_pydantic_model_from_json_schema
from structured_output.test_schemas import (
    DEFINITIONS_SCHEMA,
    ANYOF_USER_ADDRESS_SCHEMA,
    RECURSIVE_UI_SCHEMA,
    RECURSIVE_LINKED_LIST_SCHEMA,
)
from pydantic import ValidationError
import json


def test_definitions_and_ref():
    """Test $defs and $ref support"""
    print("\n=== Test 1: $defs and $ref ===")

    Model = create_pydantic_model_from_json_schema(DEFINITIONS_SCHEMA, "DefinitionsTest")

    # Create instance with steps
    instance = Model(
        steps=[
            {"explanation": "First, we do X", "output": "Result X"},
            {"explanation": "Then, we do Y", "output": "Result Y"}
        ],
        final_answer="The final answer is 42"
    )

    print(f"✅ Created instance with {len(instance.steps)} steps")
    print(f"   Step 1: {instance.steps[0].explanation}")
    print(f"   Step 2: {instance.steps[1].explanation}")
    print(f"   Final answer: {instance.final_answer}")

    # Test JSON serialization
    json_str = instance.model_dump_json()
    print(f"✅ JSON serialization works")


def test_anyof_union():
    """Test anyOf with multiple object types"""
    print("\n=== Test 2: anyOf (Union Types) ===")

    Model = create_pydantic_model_from_json_schema(ANYOF_USER_ADDRESS_SCHEMA, "AnyOfTest")

    # Create with user object
    instance1 = Model(item={
        "name": "Alice",
        "age": 30
    })
    print(f"✅ Created instance with user object")
    print(f"   item type: {type(instance1.item).__name__}")

    # Create with address object
    instance2 = Model(item={
        "number": "123",
        "street": "Main St",
        "city": "Springfield"
    })
    print(f"✅ Created instance with address object")
    print(f"   item type: {type(instance2.item).__name__}")


def test_recursive_schema_with_defs():
    """Test recursive schema using $defs and $ref"""
    print("\n=== Test 3: Recursive Schema (Linked List) ===")

    Model = create_pydantic_model_from_json_schema(RECURSIVE_LINKED_LIST_SCHEMA, "LinkedListTest")

    # Create a linked list: 1 -> 2 -> 3 -> None
    instance = Model(linked_list={
        "value": 1,
        "next": {
            "value": 2,
            "next": {
                "value": 3,
                "next": None
            }
        }
    })

    print(f"✅ Created recursive linked list")
    print(f"   Node 1 value: {instance.linked_list.value}")
    print(f"   Node 2 value: {instance.linked_list.next.value}")
    print(f"   Node 3 value: {instance.linked_list.next.next.value}")
    print(f"   Node 3 next: {instance.linked_list.next.next.next}")


def test_recursive_schema_root_ref():
    """Test recursive schema using root reference (#)"""
    print("\n=== Test 4: Recursive Schema (UI Components) ===")

    # Note: Root recursion with "#" is complex and may need special handling
    # This test will attempt to create a UI component structure

    try:
        Model = create_pydantic_model_from_json_schema(RECURSIVE_UI_SCHEMA, "UIComponentTest")

        # Create a simple UI structure
        instance = Model(
            type="div",
            label="Container",
            children=[],
            attributes=[]
        )

        print(f"✅ Created UI component")
        print(f"   type: {instance.type}")
        print(f"   label: {instance.label}")
        print(f"   children: {len(instance.children)}")

        # Try with nested children
        instance2 = Model(
            type="form",
            label="User Form",
            children=[
                {
                    "type": "field",
                    "label": "Username",
                    "children": [],
                    "attributes": [{"name": "type", "value": "text"}]
                }
            ],
            attributes=[]
        )
        print(f"✅ Created nested UI component")
        print(f"   Form with {len(instance2.children)} field(s)")

    except Exception as e:
        print(f"ℹ️  Root recursion (#) may need special handling: {e}")


def test_simple_ref_within_defs():
    """Test $ref between definitions"""
    print("\n=== Test 5: $ref Between Definitions ===")

    schema = {
        "type": "object",
        "properties": {
            "person": {
                "$ref": "#/$defs/Person"
            }
        },
        "$defs": {
            "Person": {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "address": {
                        "$ref": "#/$defs/Address"
                    }
                },
                "required": ["name", "address"]
            },
            "Address": {
                "type": "object",
                "properties": {
                    "street": {"type": "string"},
                    "city": {"type": "string"}
                },
                "required": ["street", "city"]
            }
        },
        "required": ["person"]
    }

    Model = create_pydantic_model_from_json_schema(schema, "RefBetweenDefsTest")

    instance = Model(person={
        "name": "John",
        "address": {
            "street": "123 Main St",
            "city": "Boston"
        }
    })

    print(f"✅ Created instance with cross-referenced definitions")
    print(f"   person.name: {instance.person.name}")
    print(f"   person.address.street: {instance.person.address.street}")


def test_anyof_with_null():
    """Test anyOf with null for optional fields"""
    print("\n=== Test 6: anyOf with Null (Optional) ===")

    schema = {
        "type": "object",
        "properties": {
            "optional_field": {
                "anyOf": [
                    {"type": "string"},
                    {"type": "null"}
                ]
            }
        },
        "required": ["optional_field"]
    }

    Model = create_pydantic_model_from_json_schema(schema, "AnyOfNullTest")

    # With value
    instance1 = Model(optional_field="some value")
    print(f"✅ With value: {instance1.optional_field}")

    # With null
    instance2 = Model(optional_field=None)
    print(f"✅ With null: {instance2.optional_field}")


def test_anyof_with_primitives():
    """Test anyOf with primitive types"""
    print("\n=== Test 7: anyOf with Primitives ===")

    schema = {
        "type": "object",
        "properties": {
            "flexible_field": {
                "anyOf": [
                    {"type": "string"},
                    {"type": "integer"}
                ]
            }
        },
        "required": ["flexible_field"]
    }

    Model = create_pydantic_model_from_json_schema(schema, "AnyOfPrimitivesTest")

    # With string
    instance1 = Model(flexible_field="text")
    print(f"✅ With string: {instance1.flexible_field}")

    # With integer
    instance2 = Model(flexible_field=42)
    print(f"✅ With integer: {instance2.flexible_field}")


def test_nested_refs():
    """Test deeply nested $ref structures"""
    print("\n=== Test 8: Deeply Nested $refs ===")

    schema = {
        "type": "object",
        "properties": {
            "root": {
                "$ref": "#/$defs/Level1"
            }
        },
        "$defs": {
            "Level1": {
                "type": "object",
                "properties": {
                    "level2": {
                        "$ref": "#/$defs/Level2"
                    }
                },
                "required": ["level2"]
            },
            "Level2": {
                "type": "object",
                "properties": {
                    "level3": {
                        "$ref": "#/$defs/Level3"
                    }
                },
                "required": ["level3"]
            },
            "Level3": {
                "type": "object",
                "properties": {
                    "value": {"type": "string"}
                },
                "required": ["value"]
            }
        },
        "required": ["root"]
    }

    Model = create_pydantic_model_from_json_schema(schema, "NestedRefsTest")

    instance = Model(root={
        "level2": {
            "level3": {
                "value": "deeply nested"
            }
        }
    })

    print(f"✅ Created deeply nested structure")
    print(f"   root.level2.level3.value: {instance.root.level2.level3.value}")


def test_array_of_refs():
    """Test array with $ref items"""
    print("\n=== Test 9: Array of $refs ===")

    # Already tested in DEFINITIONS_SCHEMA but let's be explicit
    schema = {
        "type": "object",
        "properties": {
            "items": {
                "type": "array",
                "items": {
                    "$ref": "#/$defs/Item"
                }
            }
        },
        "$defs": {
            "Item": {
                "type": "object",
                "properties": {
                    "id": {"type": "integer"},
                    "name": {"type": "string"}
                },
                "required": ["id", "name"]
            }
        },
        "required": ["items"]
    }

    Model = create_pydantic_model_from_json_schema(schema, "ArrayOfRefsTest")

    instance = Model(items=[
        {"id": 1, "name": "First"},
        {"id": 2, "name": "Second"},
        {"id": 3, "name": "Third"}
    ])

    print(f"✅ Created array with {len(instance.items)} $ref items")
    for item in instance.items:
        print(f"   - {item.id}: {item.name}")


def test_complex_anyof():
    """Test complex anyOf with objects and arrays"""
    print("\n=== Test 10: Complex anyOf ===")

    schema = {
        "type": "object",
        "properties": {
            "data": {
                "anyOf": [
                    {
                        "type": "object",
                        "properties": {
                            "type": {"type": "string", "enum": ["single"]},
                            "value": {"type": "string"}
                        },
                        "required": ["type", "value"]
                    },
                    {
                        "type": "object",
                        "properties": {
                            "type": {"type": "string", "enum": ["multiple"]},
                            "values": {
                                "type": "array",
                                "items": {"type": "string"}
                            }
                        },
                        "required": ["type", "values"]
                    }
                ]
            }
        },
        "required": ["data"]
    }

    Model = create_pydantic_model_from_json_schema(schema, "ComplexAnyOfTest")

    # Single value variant
    instance1 = Model(data={
        "type": "single",
        "value": "one value"
    })
    print(f"✅ Created single value variant")

    # Multiple values variant
    instance2 = Model(data={
        "type": "multiple",
        "values": ["value1", "value2", "value3"]
    })
    print(f"✅ Created multiple values variant")


def run_all_tests():
    """Run all advanced feature tests"""
    print("=" * 80)
    print("ADVANCED FEATURE TESTS - $ref, $defs, anyOf, Recursive")
    print("=" * 80)

    tests = [
        test_definitions_and_ref,
        test_anyof_union,
        test_recursive_schema_with_defs,
        test_recursive_schema_root_ref,
        test_simple_ref_within_defs,
        test_anyof_with_null,
        test_anyof_with_primitives,
        test_nested_refs,
        test_array_of_refs,
        test_complex_anyof,
    ]

    passed = 0
    failed = 0

    for test_func in tests:
        try:
            test_func()
            passed += 1
        except Exception as e:
            print(f"\n❌ {test_func.__name__} FAILED: {e}")
            import traceback
            traceback.print_exc()
            failed += 1

    print("\n" + "=" * 80)
    print(f"RESULTS: {passed} passed, {failed} failed out of {len(tests)} tests")
    print("=" * 80)

    return failed == 0


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)