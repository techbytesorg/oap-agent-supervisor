"""
Test core type support for schema parser.
Tests: Object, Array, Enum, Union types
"""

import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from oap_supervisor.utils.structured_output import create_pydantic_model_from_json_schema
from structured_output.test_schemas import (
    USER_DATA_SCHEMA,
    WEATHER_SCHEMA,
    WEATHER_OPTIONAL_SCHEMA,
    SIMPLE_ARRAY_SCHEMA,
    NESTED_OBJECT_SCHEMA,
    MULTIPLE_ENUMS_SCHEMA,
    ARRAY_OF_OBJECTS_SCHEMA,
)
from pydantic import ValidationError
import json


def test_primitives():
    """Test basic primitive types (string, number, integer, boolean)"""
    print("\n=== Test 1: Primitive Types ===")

    schema = {
        "type": "object",
        "properties": {
            "name": {"type": "string"},
            "age": {"type": "integer"},
            "score": {"type": "number"},
            "active": {"type": "boolean"}
        },
        "required": ["name", "age", "score", "active"]
    }

    Model = create_pydantic_model_from_json_schema(schema, "PrimitivesTest")

    # Valid instance
    instance = Model(name="Alice", age=30, score=95.5, active=True)
    print(f"✅ Created instance: {instance}")
    print(f"   name={instance.name}, age={instance.age}, score={instance.score}, active={instance.active}")

    # Test JSON serialization
    print(f"✅ JSON: {instance.model_dump_json()}")


def test_enum():
    """Test enum support"""
    print("\n=== Test 2: Enum Types ===")

    Model = create_pydantic_model_from_json_schema(WEATHER_SCHEMA, "WeatherTest")

    # Valid instances
    instance1 = Model(location="San Francisco", unit="F")
    print(f"✅ Created instance 1: {instance1}")

    instance2 = Model(location="Paris", unit="C")
    print(f"✅ Created instance 2: {instance2}")

    # Test invalid enum value
    try:
        instance3 = Model(location="Tokyo", unit="K")
        print(f"❌ Should have failed with invalid enum value")
    except ValidationError as e:
        print(f"✅ Correctly rejected invalid enum: {e.error_count()} errors")


def test_multiple_enums():
    """Test multiple enum fields"""
    print("\n=== Test 3: Multiple Enums ===")

    Model = create_pydantic_model_from_json_schema(MULTIPLE_ENUMS_SCHEMA, "MultipleEnumsTest")

    instance = Model(status="approved", priority="high")
    print(f"✅ Created instance: {instance}")
    print(f"   status={instance.status}, priority={instance.priority}")


def test_array_of_primitives():
    """Test array of primitive types"""
    print("\n=== Test 4: Array of Primitives ===")

    Model = create_pydantic_model_from_json_schema(SIMPLE_ARRAY_SCHEMA, "SimpleArrayTest")

    instance = Model(tags=["python", "testing", "pydantic"])
    print(f"✅ Created instance: {instance}")
    print(f"   tags={instance.tags}")


def test_array_of_objects():
    """Test array of objects"""
    print("\n=== Test 5: Array of Objects ===")

    Model = create_pydantic_model_from_json_schema(ARRAY_OF_OBJECTS_SCHEMA, "ArrayOfObjectsTest")

    instance = Model(items=[
        {"id": 1, "name": "Item 1"},
        {"id": 2, "name": "Item 2"}
    ])
    print(f"✅ Created instance: {instance}")
    print(f"   items={instance.items}")


def test_nested_object():
    """Test nested objects"""
    print("\n=== Test 6: Nested Objects ===")

    Model = create_pydantic_model_from_json_schema(NESTED_OBJECT_SCHEMA, "NestedObjectTest")

    instance = Model(user={
        "name": "Bob",
        "address": {
            "street": "123 Main St",
            "city": "Springfield"
        }
    })
    print(f"✅ Created instance: {instance}")
    print(f"   user.name={instance.user.name}")
    print(f"   user.address.street={instance.user.address.street}")
    print(f"   user.address.city={instance.user.address.city}")


def test_union_type_optional():
    """Test union types for optional fields"""
    print("\n=== Test 7: Union Types (Optional Fields) ===")

    Model = create_pydantic_model_from_json_schema(WEATHER_OPTIONAL_SCHEMA, "WeatherOptionalTest")

    # With value
    instance1 = Model(location="Boston", unit="F")
    print(f"✅ Created instance 1: {instance1}")

    # With None
    instance2 = Model(location="London", unit=None)
    print(f"✅ Created instance 2: {instance2}")


def test_user_data_with_validation():
    """Test user data schema with pattern and format"""
    print("\n=== Test 8: User Data with Validation ===")

    Model = create_pydantic_model_from_json_schema(USER_DATA_SCHEMA, "UserDataTest")

    # Valid instance
    instance = Model(
        name="John Doe",
        username="@johndoe123",
        email="john@example.com"
    )
    print(f"✅ Created instance: {instance}")
    print(f"   name={instance.name}")
    print(f"   username={instance.username}")
    print(f"   email={instance.email}")


def test_required_vs_optional():
    """Test required vs optional fields"""
    print("\n=== Test 9: Required vs Optional ===")

    schema = {
        "type": "object",
        "properties": {
            "required_field": {"type": "string"},
            "optional_field": {"type": "string"}
        },
        "required": ["required_field"]
    }

    Model = create_pydantic_model_from_json_schema(schema, "RequiredOptionalTest")

    # Valid with only required field
    instance1 = Model(required_field="value")
    print(f"✅ Created instance 1 (only required): {instance1}")

    # Valid with both fields
    instance2 = Model(required_field="value1", optional_field="value2")
    print(f"✅ Created instance 2 (both fields): {instance2}")

    # Invalid - missing required field
    try:
        instance3 = Model(optional_field="value")
        print(f"❌ Should have failed without required field")
    except ValidationError as e:
        print(f"✅ Correctly rejected missing required field: {e.error_count()} errors")


def test_all_types_combined():
    """Test schema with all types combined"""
    print("\n=== Test 10: All Types Combined ===")

    schema = {
        "type": "object",
        "properties": {
            "string_field": {"type": "string"},
            "integer_field": {"type": "integer"},
            "number_field": {"type": "number"},
            "boolean_field": {"type": "boolean"},
            "enum_field": {"type": "string", "enum": ["A", "B", "C"]},
            "array_field": {
                "type": "array",
                "items": {"type": "string"}
            },
            "nested_object": {
                "type": "object",
                "properties": {
                    "nested_field": {"type": "string"}
                },
                "required": ["nested_field"]
            }
        },
        "required": [
            "string_field", "integer_field", "number_field",
            "boolean_field", "enum_field", "array_field", "nested_object"
        ]
    }

    Model = create_pydantic_model_from_json_schema(schema, "AllTypesCombinedTest")

    instance = Model(
        string_field="test",
        integer_field=42,
        number_field=3.14,
        boolean_field=True,
        enum_field="B",
        array_field=["item1", "item2"],
        nested_object={"nested_field": "nested_value"}
    )
    print(f"✅ Created instance: {instance}")
    print(f"   JSON: {instance.model_dump_json()}")


def run_all_tests():
    """Run all core type tests"""
    print("=" * 80)
    print("CORE TYPE TESTS - Testing Object, Array, Enum, Union")
    print("=" * 80)

    tests = [
        test_primitives,
        test_enum,
        test_multiple_enums,
        test_array_of_primitives,
        test_array_of_objects,
        test_nested_object,
        test_union_type_optional,
        test_user_data_with_validation,
        test_required_vs_optional,
        test_all_types_combined,
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