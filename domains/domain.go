package domains

type Domain struct {
	Name string
}

var Domains map[string]*Domain

func init() {
	Domains = make(map[string]*Domain)
	Domains["poluianov.com"] = &Domain{Name: "poluianov.com"}
	Domains["rb-example.com"] = &Domain{Name: "rb-example.com"}
	Domains["http-server.org"] = &Domain{Name: "http-server.org"}
}
