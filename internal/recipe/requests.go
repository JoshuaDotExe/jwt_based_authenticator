package recipe

type CreateRecipeRequest struct {
	Title        string       `json:"title" binding:"required"`
	Tags         []string     `json:"tags"`
	Ingredients  Ingredients  `json:"ingredients" binding:"required"`
	Instructions Instructions `json:"instructions" binding:"required"`
}

type UpdateRecipeRequest struct {
	Title        string       `json:"title" binding:"required"`
	Tags         []string     `json:"tags"`
	Ingredients  Ingredients  `json:"ingredients" binding:"required"`
	Instructions Instructions `json:"instructions" binding:"required"`
}

type GetRecipesByOwnerIDRequest struct {
	OwnerID string `json:"owner_id" binding:"required"`
}
