package gosdk

import "github.com/pretty66/gosdk/errno"

type uploadFile struct {
	fileName string
	filePath string
}

func NewUploadFile(file map[string]string) (*uploadFile, error) {
	result := new(uploadFile)
	if file["name"] == "" || file["tmp_name"] == "" {
		return nil, errno.UPLOAD_FILE_ERROR.Add("This is not a valid array of uploadFile")
	}
	if file["error"] != "" {
		return nil, errno.UPLOAD_ENCOUNTER_ERROR.Add("The upload encounter error, please check the error first")
	}

	result.fileName = file["name"]
	result.filePath = file["tmp_name"]
	return result, nil
}
