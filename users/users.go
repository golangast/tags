package users

type User struct {
	Email string `json:"email"`
	Pkey  string `json:"pkey"`
	Prkey string `json:"prkey"`
}

type Userer interface {
	GetUserByEmail(email string) (*User, error)
	GetUserByPkey(pkey string) (*User, error)
	GetUserByPrkey(prkey string) (*User, error)
	CreateUser(user *User) error
}
