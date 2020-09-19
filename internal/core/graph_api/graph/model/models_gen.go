// Code generated by github.com/99designs/gqlgen, DO NOT EDIT.

package model

type Group struct {
	Name string `json:"name"`
}

type NewTodo struct {
	Text   string `json:"text"`
	UserID string `json:"userId"`
}

type Todo struct {
	ID     string   `json:"id"`
	Text   string   `json:"text"`
	Done   bool     `json:"done"`
	User   *User    `json:"user"`
	Groups []*Group `json:"groups"`
}

type User struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}
