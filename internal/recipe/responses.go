package recipe

type recipePreviewResponse struct {
	Title string   `json:"title"`
	Tags  []string `json:"tags"`
}

type getRecipeResponse struct {
	ID           string                `json:"id"`
	Title        string                `json:"title"`
	Tags         []string              `json:"tags"`
	Ingredients  Ingredients           `json:"ingredients"`
	Instructions Instructions          `json:"instructions"`
	Preview      recipePreviewResponse `json:"preview"`
}

type getRecipesByOwnerIDResponse struct {
	Recipes []getRecipeResponse `json:"recipes"`
}

func newGetRecipeResponse(recipe Recipe) getRecipeResponse {
	preview := recipePreviewResponse{
		Title: recipe.Title,
		Tags:  append([]string(nil), recipe.Tags...),
	}

	return getRecipeResponse{
		ID:           recipe.ID,
		Title:        recipe.Title,
		Tags:         append([]string(nil), recipe.Tags...),
		Ingredients:  recipe.Ingredients,
		Instructions: recipe.Instructions,
		Preview:      preview,
	}
}
