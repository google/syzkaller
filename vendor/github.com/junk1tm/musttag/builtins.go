package musttag

// builtins is a set of functions supported out of the box.
var builtins = []Func{
	// https://pkg.go.dev/encoding/json
	{Name: "encoding/json.Marshal", Tag: "json", ArgPos: 0},
	{Name: "encoding/json.MarshalIndent", Tag: "json", ArgPos: 0},
	{Name: "encoding/json.Unmarshal", Tag: "json", ArgPos: 1},
	{Name: "(*encoding/json.Encoder).Encode", Tag: "json", ArgPos: 0},
	{Name: "(*encoding/json.Decoder).Decode", Tag: "json", ArgPos: 0},

	// https://pkg.go.dev/encoding/xml
	{Name: "encoding/xml.Marshal", Tag: "xml", ArgPos: 0},
	{Name: "encoding/xml.MarshalIndent", Tag: "xml", ArgPos: 0},
	{Name: "encoding/xml.Unmarshal", Tag: "xml", ArgPos: 1},
	{Name: "(*encoding/xml.Encoder).Encode", Tag: "xml", ArgPos: 0},
	{Name: "(*encoding/xml.Decoder).Decode", Tag: "xml", ArgPos: 0},
	{Name: "(*encoding/xml.Encoder).EncodeElement", Tag: "xml", ArgPos: 0},
	{Name: "(*encoding/xml.Decoder).DecodeElement", Tag: "xml", ArgPos: 0},

	// https://github.com/go-yaml/yaml
	{Name: "gopkg.in/yaml.v3.Marshal", Tag: "yaml", ArgPos: 0},
	{Name: "gopkg.in/yaml.v3.Unmarshal", Tag: "yaml", ArgPos: 1},
	{Name: "(*gopkg.in/yaml.v3.Encoder).Encode", Tag: "yaml", ArgPos: 0},
	{Name: "(*gopkg.in/yaml.v3.Decoder).Decode", Tag: "yaml", ArgPos: 0},

	// https://github.com/BurntSushi/toml
	{Name: "github.com/BurntSushi/toml.Unmarshal", Tag: "toml", ArgPos: 1},
	{Name: "github.com/BurntSushi/toml.Decode", Tag: "toml", ArgPos: 1},
	{Name: "github.com/BurntSushi/toml.DecodeFS", Tag: "toml", ArgPos: 2},
	{Name: "github.com/BurntSushi/toml.DecodeFile", Tag: "toml", ArgPos: 1},
	{Name: "(*github.com/BurntSushi/toml.Encoder).Encode", Tag: "toml", ArgPos: 0},
	{Name: "(*github.com/BurntSushi/toml.Decoder).Decode", Tag: "toml", ArgPos: 0},

	// https://github.com/mitchellh/mapstructure
	{Name: "github.com/mitchellh/mapstructure.Decode", Tag: "mapstructure", ArgPos: 1},
	{Name: "github.com/mitchellh/mapstructure.DecodeMetadata", Tag: "mapstructure", ArgPos: 1},
	{Name: "github.com/mitchellh/mapstructure.WeakDecode", Tag: "mapstructure", ArgPos: 1},
	{Name: "github.com/mitchellh/mapstructure.WeakDecodeMetadata", Tag: "mapstructure", ArgPos: 1},
}
