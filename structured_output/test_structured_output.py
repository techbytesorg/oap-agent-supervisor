"""
Test script for structured output feature using remote agent authentication.
This script follows the authentication pattern from the external access POC.
"""

import os
import asyncio
import uuid
import json
from supabase import create_client, Client
from dotenv import load_dotenv
from langgraph.pregel.remote import RemoteGraph

# Load environment variables
load_dotenv()

# Supabase configuration
SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY")
USER_EMAIL = os.environ.get("USER_EMAIL")
USER_PASSWORD = os.environ.get("USER_PASSWORD")

# Agent configuration
AGENT_URL = "http://localhost:2025"  # Supervisor agent on port 2025
ASSISTANT_ID = "multi_agent_supervisor"  # Graph name from langgraph.json

# Sub-agent configuration for supervisor
# TODO: Replace these with actual assistant IDs after creating them on port 2024
SUB_AGENT_1_ID = "d45f6b26-17a5-4c73-95a0-43d41f4d97a7"  # Research assistant ID
SUB_AGENT_2_ID = "92deb9bc-7f8c-4dc2-b07e-6d1a92e3b3bb"  # Analysis assistant ID
TOOLS_AGENT_URL = "http://localhost:2024"  # Tools agent on port 2024

# Test data for comprehensive OpenAI spec coverage

# Test recipe for allergy analysis (Schema 8)
FRESHPREP_TEST_RECIPE = """
Pulled Chicken Fajitas
with Chipotle-Pineapple Sauce & Cheddar
Poultry - Local, Free Run, Antibiotic Free
Milk
Gluten
Seafood
Serves
2
Difficulty
Moderate
Time
30 Min
Ingredients
Onion
Chipotle Pepper in Adobo Sauce
Chicken Breast
Worcestershire Sauce
Aged White Cheddar Cheese
Flour Tortillas 6"
Cilantro
Assorted Mini Bell Peppers
Coconut Sugar
Green Cabbage
Pineapple-Lime Juice
Spice Blend
Lime Crema
* Pineapple-Lime Juice: Pineapple Juice , Fresh Lime Juice
* Spice Blend: Smoked Paprika , Cumin
* Lime Crema: Sour Cream , Mayonnaise , Fresh Lime Juice
"""

# Test recipe for nutrition analysis (Schema 1)
SALMON_QUINOA_RECIPE = """
Grilled Salmon with Quinoa and Roasted Vegetables
- Grilled Salmon (6oz Atlantic salmon fillet)
- Quinoa (1 cup cooked)
- Roasted Broccoli (1 cup florets)
- Olive Oil (2 tbsp for cooking)
- Lemon (1 wedge)
- Garlic and Herbs seasoning
Serves: 2 people
Estimated prep time: 30 minutes
"""

def authenticate_supabase():
    """Authenticate with Supabase and return access token and user info"""
    print(f"SUPABASE_URL: {SUPABASE_URL}")
    print(f"SUPABASE_KEY: {'***' if SUPABASE_KEY else 'None'}")
    print(f"USER_EMAIL: {USER_EMAIL}")
    print(f"USER_PASSWORD: {'***' if USER_PASSWORD else 'None'}")

    if not SUPABASE_URL or not SUPABASE_KEY:
        raise ValueError("SUPABASE_URL and SUPABASE_KEY must be set in .env file")

    if not USER_EMAIL or not USER_PASSWORD:
        raise ValueError("user_email and user_password must be set in .env file")

    supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

    response = supabase.auth.sign_in_with_password({
        "email": USER_EMAIL,
        "password": USER_PASSWORD,
    })

    # Get user info to extract user_id (same as schema_loader.py)
    access_token = response.session.access_token
    user_response = supabase.auth.get_user(access_token)
    user_id = user_response.user.id

    print(f"Authenticated user_id: {user_id}")

    return access_token, user_id

async def test_structured_output():
    """Test the structured output feature with different schemas"""

    # Authenticate and get access token and user_id
    access_token, user_id = authenticate_supabase()

    # Set up headers for authentication
    headers = {
        "accept": "application/json",
        "Authorization": f"Bearer {access_token}",
    }

    # Create remote graph connection
    remote_graph = RemoteGraph(
        ASSISTANT_ID,
        url=AGENT_URL,
        headers=headers
    )

    # Comprehensive test cases covering all OpenAI Structured Output features
    test_cases = [
        {
            "name": "Test 0: No Schema (Baseline)",
            "schema": None,
            "prompt": "What is 2 + 3?",
            "description": "Baseline test without structured output"
        },
        {
            "name": "Test 1: RecipeNutritionAnalysis (Number Constraints)",
            "schema": "RecipeNutritionAnalysis",
            "prompt": f"Analyze the nutritional content of this recipe:\n\n{SALMON_QUINOA_RECIPE}\n\nProvide calories, protein/fat/carbs in grams, number of servings, and prep time (round to nearest 5 minutes).",
            "description": "Tests: min/max, ge/le, multipleOf constraints"
        },
        {
            "name": "Test 2: IngredientClassification (Enums & Arrays)",
            "schema": "IngredientClassification",
            "prompt": "Classify this ingredient: Organic Almond Butter. Provide the ingredient name, categorize it (protein/grain/vegetable/fruit/dairy/condiment/spice), identify which dietary restrictions it fits (vegan/vegetarian/gluten-free/dairy-free/nut-free/kosher/halal), and list any allergen tags (max 5).",
            "description": "Tests: enum, array of enums, minItems/maxItems"
        },
        {
            "name": "Test 3: FoodSafetyReport ($defs & $ref)",
            "schema": "FoodSafetyReport",
            "prompt": "Generate a food safety inspection report for a commercial kitchen inspected on 2025-03-15. Inspection ID: INS-2025-0315. Found violations: 1) Improper food storage temperature in walk-in cooler (critical severity), corrective action: adjust thermostat and monitor; 2) Missing handwashing signage near prep area (minor severity), corrective action: install signage; 3) Expired ingredients in dry storage (major severity), corrective action: dispose and update inventory system. Calculate an overall safety score (0-100).",
            "description": "Tests: nested objects with $ref, array of complex objects"
        },
        {
            "name": "Test 4: MenuPlanning (Complex Nested Objects)",
            "schema": "MenuPlanning",
            "prompt": "Create a 3-day meal plan for a small restaurant starting Monday, April 1, 2025. Each day needs breakfast, lunch, and dinner. For each meal, provide dish name, main ingredients (list), and estimated cost per serving. Use a 'Spring Fresh' theme focusing on seasonal vegetables and local proteins.",
            "description": "Tests: deeply nested objects, array of complex nested structures"
        },
        {
            "name": "Test 5: RecipeInstructions (Recursive Schema)",
            "schema": "RecipeInstructions",
            "prompt": "Provide step-by-step instructions for making Homemade Sourdough Bread. Include the recipe name and total time. Break down into main steps, and for complex steps like 'Prepare the dough' or 'Shape and proof', include sub-steps. Each step should have a step number, instruction text, and duration in minutes.",
            "description": "Tests: recursive schemas, self-referencing structures"
        },
        {
            "name": "Test 6: SupplierQuote (Union Types & Pattern Validation)",
            "schema": "SupplierQuote",
            "prompt": "Generate a supplier quote: Supplier name is 'Fresh Farms Co.', contact email john.smith@freshfarms.com, phone number (555) 123-4567, quoting $450.00 for organic produce delivery. Expected delivery date is 2025-04-15. Add optional notes about requiring refrigerated transport.",
            "description": "Tests: pattern validation (email, phone, date), union with null"
        },
        {
            "name": "Test 7: QualityInspection (Multiple Enums & Format Validation)",
            "schema": "QualityInspection",
            "prompt": "Create a quality control inspection record: Batch ID BT-2025-0315 for processed tomatoes. Inspector email: qa.inspector@foodco.com. Inspection datetime: 2025-03-15T14:30:00. Assign a quality grade (A/B/C/D/F), set status (pending/approved/rejected/review_required), and list inspection findings such as color consistency, texture, no defects found.",
            "description": "Tests: multiple enums, format validation (email, date-time), pattern (batch ID)"
        },
        {
            "name": "Test 8: AllergyAnalysisResponse (Keep Existing)",
            "schema": "AllergyAnalysisResponse",
            "prompt": f"Analyze this recipe for food allergens:\n\n{FRESHPREP_TEST_RECIPE}\n\nIdentify high-risk allergens with reasons, and provide recommendations for people with allergies.",
            "description": "Tests: array of nested objects (proven working)"
        }
    ]

    # Convert to old format for compatibility
    formatted_test_cases = []
    for test in test_cases:
        case = {
            "name": test["name"],
            "config": {
                "configurable": {
                    "thread_id": str(uuid.uuid4()),
                    "x-supabase-access-token": access_token,
                    # Supervisor-specific configuration
                    "agents": [
                        {
                            "deployment_url": TOOLS_AGENT_URL,
                            "agent_id": SUB_AGENT_1_ID,
                            "name": "research_assistant"
                        },
                        {
                            "deployment_url": TOOLS_AGENT_URL,
                            "agent_id": SUB_AGENT_2_ID,
                            "name": "analysis_assistant"
                        }
                    ],
                    "system_prompt": "You are a supervisor AI coordinating specialist agents. Delegate tasks to research_assistant for information gathering and analysis_assistant for breaking down complex topics.",
                    "supervisor_model": "openai:gpt-4o-mini"
                }
            },
            "prompt": test["prompt"],
            "description": test["description"]
        }
        if test["schema"]:
            case["config"]["configurable"]["user_id"] = user_id
            case["config"]["configurable"]["OutputSchemaName"] = test["schema"]
        formatted_test_cases.append(case)

    test_cases = formatted_test_cases

    # Run test cases
    passed = 0
    failed = 0

    for i, test_case in enumerate(test_cases, 1):
        print(f"\n{'='*80}")
        print(f"{test_case['name']}")
        print(f"Description: {test_case['description']}")
        print(f"{'='*80}")

        try:
            # Invoke the graph
            print(f"Sending request to LangGraph agent...")
            result = await remote_graph.ainvoke({
                "messages": [{"role": "user", "content": test_case["prompt"]}]
            }, config=test_case["config"])

            # Check if structured output is expected
            schema_name = test_case["config"]["configurable"].get("OutputSchemaName")
            if schema_name:
                structured_response = result.get("structured_response")
                if structured_response:
                    print(f"\n✅ SUCCESS - Structured output received ({schema_name}):")
                    print("-" * 80)
                    # Pretty print if it's JSON
                    try:
                        if isinstance(structured_response, str):
                            parsed = json.loads(structured_response)
                            print(json.dumps(parsed, indent=2))
                        else:
                            print(json.dumps(structured_response, indent=2))
                    except:
                        print(structured_response)
                    passed += 1
                else:
                    print(f"\n❌ FAILED - No structured response found")
                    print("Text output received instead:")
                    print(result["messages"][-1]["content"])
                    failed += 1
            else:
                print(f"\n✅ Text output (no schema expected):")
                print(result["messages"][-1]["content"])
                passed += 1

        except Exception as e:
            print(f"\n❌ FAILED - Error in test case: {e}")
            import traceback
            traceback.print_exc()
            failed += 1

    # Summary
    print(f"\n{'='*80}")
    print(f"TEST SUMMARY")
    print(f"{'='*80}")
    print(f"Total tests: {len(test_cases)}")
    print(f"Passed: {passed}")
    print(f"Failed: {failed}")
    if failed == 0:
        print(f"\n🎉 All tests passed! Full OpenAI spec coverage demonstrated.")
    else:
        print(f"\n⚠️  Some tests failed. Review output above.")
    print(f"{'='*80}")

async def main():
    """Main function to run structured output tests"""
    print("Starting structured output tests...")
    print(f"Agent URL: {AGENT_URL}")
    print(f"Assistant ID: {ASSISTANT_ID}")

    try:
        await test_structured_output()
        print(f"\n{'='*50}")
        print("All tests completed!")
    except Exception as e:
        print(f"Error during testing: {e}")

if __name__ == "__main__":
    asyncio.run(main())