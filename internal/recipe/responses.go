package recipe

type getRecipeResponse struct {
	ID           string       `json:"id"`
	Title        string       `json:"title"`
	Ingredients  Ingredients  `json:"ingredients"`
	Instructions Instructions `json:"instructions"`
}
