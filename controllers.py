
def validateData(data):
	invalid = ('"', "'")
	for x in data:
		if invalid in data[x]:
			for x in invalid:
				data[x] = data[x].replace(x, '')
