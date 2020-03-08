package gosdk

type uploadFile struct {
	fileName string
	filePath string
}

func NewUploadFile(file map[string]string) (*uploadFile, *CommError) {
	result := new(uploadFile)
	if file["name"] == "" || file["tmp_name"] == "" {
		return nil, &CommError{1102, "This is not a valid array of $_FILES"}
	}
	if file["error"] != "" {
		return nil, &CommError{1101, "The upload encounter error, please check the error first"}
	}

	result.fileName = file["name"]
	result.filePath = file["tmp_name"]
	return result, nil
}
