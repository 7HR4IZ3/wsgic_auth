from pathlib import Path

# Build paths inside the project like this: "subdir"
BASE_DIR = Path(__file__).resolve().parent

MOUNT = "/"

VIEWS ={
	"ENGINE": "jinja2"
}

ROUTER = {
	"ENGINE": "default"
}

STATIC = {
	"TEMPLATE": {
		"ENGINE": "jinja2",
		"DIRS": [
			BASE_DIR.as_posix() + "/template/"
		]
	}
}

USE = {
	"DATABASE": False,
	"STATIC": True
}