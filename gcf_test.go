package gcf

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"testing"
)

func TestTriggerScaling(t *testing.T) {
	// startup
	dataStoreHost := exec.Command("gcloud", "beta", "emulators", "datastore", "start", "--host-port=localhost")
	go dataStoreHost.Run()
	pubSubHost := exec.Command("gcloud", "beta", "emulators", "pubsub", "start", "--host-port=localhost")
	go pubSubHost.Run()
	os.Setenv("DATASTORE_DATASET", "project-test")
	os.Setenv("DATASTORE_EMULATOR_HOST", "localhost:8081")
	os.Setenv("DATASTORE_EMULATOR_HOST_PATH", "localhost:8081/datastore")
	os.Setenv("DATASTORE_HOST", "http://localhost:8081")
	os.Setenv("DATASTORE_PROJECT_ID", "project-test")
	os.Setenv("PUBSUB_EMULATOR_HOST", "localhost:8080")
	os.Setenv("PROJECT_ID", "project-test")
	// run tests
	addTest := DataStoreIncident{
		IncidentID:      "abcd",
		PolicyName:      "add",
		State:           "foo",
		StartedAt:       123456,
		ClosedTimestamp: "today",
		Condition: DataStoreCondition{
			IncidentID: "abcd",
			PolicyName: "add",
		},
		SqlMasterInstance: "sql-writer",
		ReplicaBaseName:   "sql-reader",
		Documentation: DataStoreDocumentation{
			Content:  `{ "replica_basename":"slq-reader-", "sql_master_instance":"sql-writer", "instance_group":"sql-writer", "action":"add" }`,
			MimeType: "MEME",
		},
		InProgress:    true,
		Action:        "add",
		LastProcess:   "",
		OperationID:   "",
		LastUpdated:   "",
		LastUpdatedBy: "",
	}
	addIncident := IncidentRequest{
		Incident: addTest,
	}
	b, _ := json.Marshal(&addIncident)
	r := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", bytes.NewBuffer(b))
	TriggerScaling(r, req)
	if r.Code != 200 {
		t.Error("bad code")
		t.FailNow()
	}

	// clean up
	dataStoreShutDownRequest, _ := http.NewRequest("POST", "http://localhost:8081/shutdown", nil)
	pubSubResetRequest, _ := http.NewRequest("POST", "http://localhost:8080/reset", nil)
	pubSubShutdownRequest, _ := http.NewRequest("POST", "http://localhost:8080/shutdown", nil)
	httpClient := &http.Client{}
	_, err := httpClient.Do(dataStoreShutDownRequest)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	_, err = httpClient.Do(pubSubResetRequest)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	_, err = httpClient.Do(pubSubShutdownRequest)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
}
