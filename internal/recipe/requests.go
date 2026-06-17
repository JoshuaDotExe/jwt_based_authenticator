package recipe

type CreateRecipeRequest struct {
	Title        string       `json:"title" binding:"required"`
	Ingredients  Ingredients  `json:"ingredients" binding:"required"`
	Instructions Instructions `json:"instructions" binding:"required"`
}

type UpdateRecipeRequest struct {
	Title        string       `json:"title" binding:"required"`
	Ingredients  Ingredients  `json:"ingredients" binding:"required"`
	Instructions Instructions `json:"instructions" binding:"required"`
}
