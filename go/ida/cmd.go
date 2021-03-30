package ida

type Command interface {
	Run() error
}
