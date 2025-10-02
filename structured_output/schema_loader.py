"""
Schema management script for CRUD operations on LangGraph memory store schemas.
"""

import os
import asyncio
from pydantic import BaseModel, Field
from typing import List
from langgraph_sdk import get_client
from dotenv import load_dotenv
from supabase import create_client, Client

# Load environment variables
load_dotenv()

# Supabase configuration
SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY")
USER_EMAIL = os.environ.get("USER_EMAIL")
USER_PASSWORD = os.environ.get("USER_PASSWORD")

# LangGraph configuration
LANGGRAPH_API_URL = "http://localhost:2025"  # Change if needed

def authenticate_supabase() -> str:
    """Authenticate with Supabase and return access token"""
    supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
    response = supabase.auth.sign_in_with_password({
        "email": USER_EMAIL,
        "password": USER_PASSWORD,
    })
    if response.session is None:
        raise RuntimeError(f"Supabase authentication failed: {response}")
    return response.session.access_token

def get_authenticated_client():
    """Get authenticated LangGraph client"""
    access_token = authenticate_supabase()
    headers = {
        "accept": "application/json",
        "Authorization": f"Bearer {access_token}",
    }
    return get_client(url=LANGGRAPH_API_URL, headers=headers)

# Define test schemas using Pydantic - Full OpenAI Spec Coverage

# Schema 1: Number constraints (min/max, multipleOf, exclusive bounds)
class RecipeNutritionAnalysis(BaseModel):
    """Nutritional analysis of a recipe with validation constraints"""
    calories: int = Field(..., ge=0, le=10000, description="Total calories per serving")
    protein_grams: float = Field(..., ge=0, description="Protein in grams")
    fat_grams: float = Field(..., ge=0, description="Fat in grams")
    carbs_grams: float = Field(..., ge=0, description="Carbohydrates in grams")
    servings: int = Field(..., ge=1, le=20, description="Number of servings")
    prep_time_minutes: int = Field(..., ge=1, multiple_of=5, description="Preparation time in minutes (multiples of 5)")


# Schema 2: Enums and arrays with constraints
class IngredientClassification(BaseModel):
    """Classification of a food ingredient"""
    ingredient_name: str = Field(..., description="Name of the ingredient")
    category: str = Field(..., description="Primary food category",
                          json_schema_extra={"enum": ["protein", "grain", "vegetable", "fruit", "dairy", "condiment", "spice"]})
    dietary_restrictions: List[str] = Field(..., description="Dietary restrictions this ingredient fits",
                                           json_schema_extra={"items": {"enum": ["vegan", "vegetarian", "gluten-free", "dairy-free", "nut-free", "kosher", "halal"]}})
    allergen_tags: List[str] = Field(..., min_length=0, max_length=5, description="Allergen warnings (max 5)")


# Schema 3: $defs and $ref - nested structures
class Violation(BaseModel):
    """A food safety violation"""
    violation_type: str = Field(..., description="Type of violation")
    severity: str = Field(..., description="Severity level",
                         json_schema_extra={"enum": ["minor", "major", "critical"]})
    description: str = Field(..., description="Detailed description of the violation")
    corrective_action: str = Field(..., description="Required corrective action")


class FoodSafetyReport(BaseModel):
    """Food safety inspection report with nested violations"""
    inspection_id: str = Field(..., description="Unique inspection identifier")
    inspection_date: str = Field(..., description="Date of inspection (YYYY-MM-DD)")
    violations: List[Violation] = Field(..., description="List of violations found")
    overall_score: int = Field(..., ge=0, le=100, description="Overall safety score (0-100)")


# Schema 4: Complex nested objects - array of objects
class MealOption(BaseModel):
    """A single meal option"""
    dish_name: str = Field(..., description="Name of the dish")
    main_ingredients: List[str] = Field(..., min_length=1, description="List of main ingredients")
    estimated_cost: float = Field(..., gt=0, description="Estimated cost per serving")


class DailyMenu(BaseModel):
    """Menu for a single day"""
    day_name: str = Field(..., description="Day of the week")
    date: str = Field(..., description="Date (YYYY-MM-DD)")
    breakfast: MealOption = Field(..., description="Breakfast option")
    lunch: MealOption = Field(..., description="Lunch option")
    dinner: MealOption = Field(..., description="Dinner option")


class MenuPlanning(BaseModel):
    """Weekly menu planning for a restaurant"""
    week_start_date: str = Field(..., description="Start date of the week (YYYY-MM-DD)")
    daily_menus: List[DailyMenu] = Field(..., min_length=1, max_length=7, description="Daily menu plans")
    theme: str = Field(..., description="Overall theme for the week")


# Schema 5: Recursive schemas with $defs
class RecipeStep(BaseModel):
    """A recipe step that can have sub-steps"""
    step_number: int = Field(..., ge=1, description="Step number in sequence")
    instruction: str = Field(..., description="Instruction text")
    duration_minutes: int = Field(..., ge=0, description="Time required for this step")
    sub_steps: List['RecipeStep'] = Field(default_factory=list, description="Optional sub-steps")


# Enable forward references
RecipeStep.model_rebuild()


class RecipeInstructions(BaseModel):
    """Recipe instructions with potentially nested steps"""
    recipe_name: str = Field(..., description="Name of the recipe")
    total_time_minutes: int = Field(..., ge=0, description="Total preparation and cooking time")
    steps: List[RecipeStep] = Field(..., min_length=1, description="List of preparation steps")


# Schema 6: Union types (anyOf with null) and string validation
class SupplierQuote(BaseModel):
    """Supplier quotation with optional fields"""
    supplier_name: str = Field(..., description="Name of the supplier company")
    contact_email: str = Field(..., description="Contact email address",
                               pattern=r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
    contact_phone: str = Field(..., description="Contact phone number",
                              pattern=r'^\(\d{3}\) \d{3}-\d{4}$')
    quoted_price: float = Field(..., gt=0, description="Quoted price in dollars")
    delivery_date: str = Field(..., description="Expected delivery date (YYYY-MM-DD)",
                              pattern=r'^\d{4}-\d{2}-\d{2}$')
    notes: str | None = Field(None, description="Optional notes about the quote")


# Schema 7: Multiple enums and format validation
class QualityInspection(BaseModel):
    """Quality control inspection record"""
    inspector_email: str = Field(..., description="Inspector's email",
                                pattern=r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
    inspection_datetime: str = Field(..., description="Date and time of inspection (ISO format)",
                                    pattern=r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}$')
    batch_id: str = Field(..., description="Batch identifier",
                         pattern=r'^BT-\d{4}-\d{4}$')
    quality_grade: str = Field(..., description="Quality grade",
                              json_schema_extra={"enum": ["A", "B", "C", "D", "F"]})
    status: str = Field(..., description="Inspection status",
                       json_schema_extra={"enum": ["pending", "approved", "rejected", "review_required"]})
    findings: List[str] = Field(..., description="List of inspection findings")


# Schema 8: Keep existing allergy analysis (already works well)
class AllergenEntry(BaseModel):
    allergen: str = Field(..., description="Name of the allergen, e.g., 'peanut'")
    reason: str = Field(..., description="Reason this allergen is high risk")


class AllergyAnalysisResponse(BaseModel):
    high_risk_allergen: List[AllergenEntry] = Field(description="List of allergen-risk mappings")
    recommendation: str = Field(description="Overall recommendation for handling this recipe")

async def store_schemas():
    """Store all test schemas in the LangGraph memory store"""
    client = get_authenticated_client()

    # Get user info to build namespace
    access_token = authenticate_supabase()
    supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
    user_response = supabase.auth.get_user(access_token)
    user_id = user_response.user.id

    # All 8 comprehensive schemas covering OpenAI specs
    schemas = {
        "RecipeNutritionAnalysis": RecipeNutritionAnalysis.model_json_schema(),
        "IngredientClassification": IngredientClassification.model_json_schema(),
        "FoodSafetyReport": FoodSafetyReport.model_json_schema(),
        "MenuPlanning": MenuPlanning.model_json_schema(),
        "RecipeInstructions": RecipeInstructions.model_json_schema(),
        "SupplierQuote": SupplierQuote.model_json_schema(),
        "QualityInspection": QualityInspection.model_json_schema(),
        "AllergyAnalysisResponse": AllergyAnalysisResponse.model_json_schema(),
    }

    print(f"Storing {len(schemas)} schemas for user {user_id}...")
    for name, schema_json in schemas.items():
        # Use [user_id, "schemas"] as namespace to satisfy auth requirements
        await client.store.put_item([user_id, "schemas"], name, schema_json)
        print(f"  ✅ Stored schema: {name}")

async def list_schemas() -> List[str]:
    """List all available schemas in the memory store"""
    client = get_authenticated_client()

    # Get user info to build namespace
    access_token = authenticate_supabase()
    supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
    user_response = supabase.auth.get_user(access_token)
    user_id = user_response.user.id

    results = await client.store.search_items([user_id, "schemas"])
    schemas = [item["key"] for item in results["items"]]
    print("Available schemas:")
    for schema in schemas:
        print(f"  - {schema}")
    return schemas

async def delete_schema(schema_name: str):
    """Delete a schema from the memory store"""
    client = get_authenticated_client()

    # Get user info to build namespace
    access_token = authenticate_supabase()
    supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
    user_response = supabase.auth.get_user(access_token)
    user_id = user_response.user.id

    await client.store.delete_item([user_id, "schemas"], schema_name)
    print(f"Deleted schema: {schema_name}")

async def main():
    print("Loading test schemas for structured output...")
    await store_schemas()
    await list_schemas()

    # Example: delete a schema (uncomment to test)
    # await delete_schema("OutputSchemaB")
    # await list_schemas()

if __name__ == "__main__":
    asyncio.run(main())
