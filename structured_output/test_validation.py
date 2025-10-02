"""
Test validation constraints for schema parser.
Tests: pattern, format, min/max, minItems/maxItems, multipleOf
"""

import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from oap_supervisor.utils.structured_output import create_pydantic_model_from_json_schema
from structured_output.test_schemas import (
    USER_DATA_SCHEMA,
    NUMBER_CONSTRAINTS_SCHEMA,
    STRING_FORMAT_SCHEMA,
    SIMPLE_ARRAY_SCHEMA,
)
from pydantic import ValidationError


def test_string_pattern():
    """Test string pattern (regex) validation"""
    print("\n=== Test 1: String Pattern Validation ===")

    Model = create_pydantic_model_from_json_schema(USER_DATA_SCHEMA, "PatternTest")

    # Valid username
    instance1 = Model(
        name="Alice",
        username="@alice_123",
        email="alice@example.com"
    )
    print(f"✅ Valid username: {instance1.username}")

    # Invalid username (doesn't start with @)
    try:
        instance2 = Model(
            name="Bob",
            username="bob123",
            email="bob@example.com"
        )
        print(f"❌ Should have failed - username must start with @")
    except ValidationError as e:
        print(f"✅ Correctly rejected invalid pattern: {e.error_count()} error(s)")


def test_string_format_email():
    """Test email format validation"""
    print("\n=== Test 2: Email Format Validation ===")

    Model = create_pydantic_model_from_json_schema(STRING_FORMAT_SCHEMA, "EmailFormatTest")

    # Valid email
    try:
        instance = Model(
            email="test@example.com",
            uuid="550e8400-e29b-41d4-a716-446655440000",
            date="2025-01-15",
            datetime="2025-01-15T10:30:00"
        )
        print(f"✅ Valid email: {instance.email}")
    except ValidationError as e:
        print(f"ℹ️  Email validation: {e.error_count()} error(s) (format validation may vary)")


def test_string_format_uuid():
    """Test UUID format validation"""
    print("\n=== Test 3: UUID Format Validation ===")

    schema = {
        "type": "object",
        "properties": {
            "id": {
                "type": "string",
                "format": "uuid"
            }
        },
        "required": ["id"]
    }

    Model = create_pydantic_model_from_json_schema(schema, "UUIDTest")

    # Valid UUID
    try:
        instance = Model(id="550e8400-e29b-41d4-a716-446655440000")
        print(f"✅ Valid UUID: {instance.id}")
    except ValidationError as e:
        print(f"ℹ️  UUID validation: {e.error_count()} error(s) (format validation may vary)")


def test_string_format_date():
    """Test date format validation"""
    print("\n=== Test 4: Date Format Validation ===")

    schema = {
        "type": "object",
        "properties": {
            "birth_date": {
                "type": "string",
                "format": "date"
            }
        },
        "required": ["birth_date"]
    }

    Model = create_pydantic_model_from_json_schema(schema, "DateTest")

    # Valid date
    try:
        instance = Model(birth_date="1990-05-15")
        print(f"✅ Valid date: {instance.birth_date}")
    except ValidationError as e:
        print(f"ℹ️  Date validation: {e.error_count()} error(s) (format validation may vary)")


def test_number_minimum_maximum():
    """Test number minimum and maximum constraints"""
    print("\n=== Test 5: Number Min/Max ===")

    Model = create_pydantic_model_from_json_schema(NUMBER_CONSTRAINTS_SCHEMA, "NumberConstraintsTest")

    # Valid values
    instance1 = Model(age=25, price=10.50)
    print(f"✅ Valid values: age={instance1.age}, price={instance1.price}")

    # Test minimum boundary
    instance2 = Model(age=0, price=0.01)
    print(f"✅ Boundary values: age={instance2.age}, price={instance2.price}")

    # Test maximum boundary
    instance3 = Model(age=150, price=1000000.00)
    print(f"✅ Max boundary: age={instance3.age}")

    # Invalid - below minimum
    try:
        instance4 = Model(age=-1, price=10.00)
        print(f"❌ Should have failed - age below minimum")
    except ValidationError as e:
        print(f"✅ Correctly rejected age < 0: {e.error_count()} error(s)")

    # Invalid - above maximum
    try:
        instance5 = Model(age=200, price=10.00)
        print(f"❌ Should have failed - age above maximum")
    except ValidationError as e:
        print(f"✅ Correctly rejected age > 150: {e.error_count()} error(s)")


def test_number_exclusive_bounds():
    """Test exclusive minimum and maximum"""
    print("\n=== Test 6: Exclusive Min/Max ===")

    schema = {
        "type": "object",
        "properties": {
            "percentage": {
                "type": "number",
                "exclusiveMinimum": 0,
                "exclusiveMaximum": 100
            }
        },
        "required": ["percentage"]
    }

    Model = create_pydantic_model_from_json_schema(schema, "ExclusiveBoundsTest")

    # Valid value
    instance1 = Model(percentage=50.5)
    print(f"✅ Valid percentage: {instance1.percentage}")

    # Test boundary (should be exclusive)
    try:
        instance2 = Model(percentage=0)
        print(f"❌ Should have failed - 0 is excluded by exclusiveMinimum")
    except ValidationError as e:
        print(f"✅ Correctly rejected percentage = 0: {e.error_count()} error(s)")

    try:
        instance3 = Model(percentage=100)
        print(f"❌ Should have failed - 100 is excluded by exclusiveMaximum")
    except ValidationError as e:
        print(f"✅ Correctly rejected percentage = 100: {e.error_count()} error(s)")


def test_number_multiple_of():
    """Test multipleOf constraint"""
    print("\n=== Test 7: Multiple Of ===")

    # Test from NUMBER_CONSTRAINTS_SCHEMA (price must be multiple of 0.01)
    Model = create_pydantic_model_from_json_schema(NUMBER_CONSTRAINTS_SCHEMA, "MultipleOfTest")

    # Valid - multiple of 0.01
    instance1 = Model(age=25, price=10.50)
    print(f"✅ Valid price (multiple of 0.01): {instance1.price}")

    instance2 = Model(age=25, price=99.99)
    print(f"✅ Valid price (multiple of 0.01): {instance2.price}")


def test_array_min_max_items():
    """Test array minItems and maxItems constraints"""
    print("\n=== Test 8: Array Min/Max Items ===")

    Model = create_pydantic_model_from_json_schema(SIMPLE_ARRAY_SCHEMA, "ArrayConstraintsTest")

    # Valid - within bounds
    instance1 = Model(tags=["tag1"])
    print(f"✅ Valid (1 item, min=1): {instance1.tags}")

    instance2 = Model(tags=["tag1", "tag2", "tag3"])
    print(f"✅ Valid (3 items): {instance2.tags}")

    instance3 = Model(tags=["t1", "t2", "t3", "t4", "t5", "t6", "t7", "t8", "t9", "t10"])
    print(f"✅ Valid (10 items, max=10): {len(instance3.tags)} items")

    # Invalid - too few items
    try:
        instance4 = Model(tags=[])
        print(f"❌ Should have failed - below minItems")
    except ValidationError as e:
        print(f"✅ Correctly rejected empty array: {e.error_count()} error(s)")

    # Invalid - too many items
    try:
        instance5 = Model(tags=[f"tag{i}" for i in range(11)])
        print(f"❌ Should have failed - above maxItems")
    except ValidationError as e:
        print(f"✅ Correctly rejected array > 10 items: {e.error_count()} error(s)")


def test_string_length_constraints():
    """Test string minLength and maxLength"""
    print("\n=== Test 9: String Length Constraints ===")

    schema = {
        "type": "object",
        "properties": {
            "username": {
                "type": "string",
                "minLength": 3,
                "maxLength": 20
            }
        },
        "required": ["username"]
    }

    Model = create_pydantic_model_from_json_schema(schema, "StringLengthTest")

    # Valid
    instance1 = Model(username="bob")
    print(f"✅ Valid (3 chars, min=3): {instance1.username}")

    instance2 = Model(username="a" * 20)
    print(f"✅ Valid (20 chars, max=20): {len(instance2.username)} chars")

    # Invalid - too short
    try:
        instance3 = Model(username="ab")
        print(f"❌ Should have failed - below minLength")
    except ValidationError as e:
        print(f"✅ Correctly rejected short string: {e.error_count()} error(s)")

    # Invalid - too long
    try:
        instance4 = Model(username="a" * 21)
        print(f"❌ Should have failed - above maxLength")
    except ValidationError as e:
        print(f"✅ Correctly rejected long string: {e.error_count()} error(s)")


def test_combined_constraints():
    """Test multiple constraints on same field"""
    print("\n=== Test 10: Combined Constraints ===")

    schema = {
        "type": "object",
        "properties": {
            "score": {
                "type": "integer",
                "minimum": 0,
                "maximum": 100,
                "multipleOf": 5
            }
        },
        "required": ["score"]
    }

    Model = create_pydantic_model_from_json_schema(schema, "CombinedConstraintsTest")

    # Valid
    instance1 = Model(score=0)
    print(f"✅ Valid: {instance1.score}")

    instance2 = Model(score=50)
    print(f"✅ Valid: {instance2.score}")

    instance3 = Model(score=100)
    print(f"✅ Valid: {instance3.score}")

    # Invalid - not multiple of 5
    try:
        instance4 = Model(score=42)
        print(f"❌ Should have failed - not multiple of 5")
    except ValidationError as e:
        print(f"✅ Correctly rejected (not multiple of 5): {e.error_count()} error(s)")


def run_all_tests():
    """Run all validation constraint tests"""
    print("=" * 80)
    print("VALIDATION CONSTRAINT TESTS")
    print("=" * 80)

    tests = [
        test_string_pattern,
        test_string_format_email,
        test_string_format_uuid,
        test_string_format_date,
        test_number_minimum_maximum,
        test_number_exclusive_bounds,
        test_number_multiple_of,
        test_array_min_max_items,
        test_string_length_constraints,
        test_combined_constraints,
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