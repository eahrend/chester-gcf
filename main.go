package gcf

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"text/template"

	"cloud.google.com/go/datastore"
	"cloud.google.com/go/pubsub"
	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	secretmanagerpb "google.golang.org/genproto/googleapis/cloud/secretmanager/v1"
)

// TODO: Since this is open source now I can use the chester-models repo

// consts used for incident data steps
// GCFPush means the last updated step was it was received from stackdriver to GCF
const GCFPush string = "gcf_push"

// DaemonAck means the daemon acknowledged the incident
const DaemonAck string = "daemon_ack"

// InstanceInsert means the daemon attempted to modify the instance via the sqladmin API. See DataStoreIncident.OperationID for what operation to query.
const InstanceInsert string = "instance_insert"

// ConfigUpdate means the daemon created the instance, and updated the configmap for the related proxysql instance
const ConfigUpdate string = "config_update"

// ProxySQL restart means the proxysql deployment was restarted
const ProxysqlRestart string = "proxysql_restart"

// StatusCheck means it was in the process of waiting to recheck the status of this incident from datastore.
const StatusCheck string = "status_check"

// IncidentRequest stores high level data about an incident triggered from GCP monitoring
type IncidentRequest struct {
	Incident DataStoreIncident `json:"incident"`
}

type InstanceMetaData struct {
	InstanceMetaData string `json:"instance_metadata" datastore:"instance_metadata"`
}

// DataStoreIncident is the incident structure inside of datastore
type DataStoreIncident struct {
	IncidentID        string                 `json:"incident_id"`
	PolicyName        string                 `json:"policy_name"`
	State             string                 `json:"state"`
	StartedAt         int64                  `json:"started_at"`
	ClosedTimestamp   string                 `json:"closed_timestamp"`
	Condition         DataStoreCondition     `json:"condition"`
	SqlMasterInstance string                 `json:"sql_master_instance"`
	ReplicaBaseName   string                 `json:"replica_basename"`
	Documentation     DataStoreDocumentation `json:"documentation"`
	InProgress        bool                   `json:"in_progress,omitempty"`
	Action            string                 `json:"action"`
	// Last process will give us the last thing the daemon attempted to do before it was killed.
	LastProcess string `json:"last_process"`
	// Operation ID is the way we can query an operation that was done against the sql admin API
	OperationID string `json:"operation_id"`
	// Last updated shows us when the incident was last updated, I'll add the RFC to this comment later
	LastUpdated string `json:"last_updated"`
	// Last updated by shows us what actor last updated this request.
	LastUpdatedBy string `json:"last_updated_by"`
}

// DataStoreDocumentation is metadata about the alert stored in the documentation attribute
type DataStoreDocumentation struct {
	Content  string `json:"content"`
	MimeType string `json:"mime_type"`
}

// InicidentMetaData contains metadata about instances in the incident
type InicidentMetaData struct {
	ReplicaBaseName   string `json:"replica_basename"`
	SqlMasterInstance string `json:"sql_master_instance"`
	Action            string `json:"action"`
	InstanceGroup     string `json:"instance_group"`
}

// DataStoreCondition contains policy data about the incident
type DataStoreCondition struct {
	IncidentID string `json:"incident_id"`
	PolicyName string `json:"policy_name"`
}

// ProxySqlConfig is the datastore/libconfig struct that configures a proxysql instance
type ProxySqlConfig struct {
	DataDir         string                       `libconfig:"datadir" json:"datadir"`
	AdminVariables  ProxySqlConfigAdminVariables `libconfig:"admin_variables" json:"admin_variables"`
	MysqlVariables  ProxySqlConfigMysqlVariables `libconfig:"mysql_variables" json:"mysql_variables"`
	MySqlServers    []ProxySqlMySqlServer        `libconfig:"mysql_servers" json:"mysql_servers"`
	MySqlUsers      []ProxySqlMySqlUser          `libconfig:"mysql_users" json:"mysql_users"`
	MySqlQueryRules []ProxySqlMySqlQueryRule     `libconfig:"mysql_query_rules" json:"mysql_query_rules"`
	ReadHostGroup   int                          `json:"read_hostgroup"`
	WriteHostGroup  int                          `json:"write_hostgroup"`
	// int here is either 0 = false or 1 = true.
	UseSSL int `json:"use_ssl"`
	// These are the top level certs that I will not be using, here for prosterity
	KeyData  string `json:"key,omitempty"`
	CertData string `json:"cert,omitempty"`
	CAData   string `json:"ca_data,omitempty"`
}

type ProxySqlConfigAdminVariables struct {
	AdminCredentials string `libconfig:"admin_credentials" json:"admin_credentials"`
	MysqlIFaces      string `libconfig:"mysql_ifaces" json:"mysql_ifaces"`
	RefreshInterval  int64  `libconfig:"refresh_interval" json:"refresh_interval"`
}

type ProxySqlMySqlQueryRule struct {
	RuleID   int    `libconfig:"rule_id" json:"rule_id"`
	Username string `libconfig:"username" json:"username"`
	// 0 or 1
	Active               int    `libconfig:"active" json:"active"`
	MatchDigest          string `libconfig:"match_digest" json:"match_digest"`
	DestinationHostgroup int    `libconfig:"destination_hostgroup" json:"destination_hostgroup"`
	// 0 or 1
	Apply   int    `libconfig:"apply" json:"apply"`
	Comment string `libconfig:"comment" json:"comment"`
}

type ProxySqlMySqlUser struct {
	Username         string `libconfig:"username" json:"username"`
	Password         string `libconfig:"password" json:"password"`
	DefaultHostgroup int    `libconfig:"default_hostgroup" json:"default_hostgroup"`
	// 0 or 1
	Active        int    `libconfig:"active" json:"active"`
	InstanceGroup string `json:"instance_group"`
}

// ProxySqlMySqlServer contains data about the sql server
type ProxySqlMySqlServer struct {
	Address        string `libconfig:"address" json:"address"`
	Port           int64  `libconfig:"port" json:"port"`
	Hostgroup      int    `libconfig:"hostgroup" json:"hostgroup"`
	MaxConnections int64  `libconfig:"max_connections" json:"max_connections"`
	Comment        string `libconfig:"comment" json:"comment"`
	UseSSL         int    `libconfig:"use_ssl" json:"use_ssl"`
	// These are more here for future features I'm asking for or updating myself
	// They're omit empty because they're not really supported anywhere, moreso scaffolding
	KeyData  string `json:"key_data,omitempty"`
	CAData   string `json:"ca_data,omitempty"`
	CertData string `json:"cert_data,omitempty"`
}

// ProxySqlConfigMysqlVariables are the variables that get loaded into global_variables that are prefixed with mysql-
type ProxySqlConfigMysqlVariables struct {
	Threads                int    `libconfig:"threads" json:"threads"`
	MaxConnections         int64  `libconfig:"max_connections" json:"max_connections"`
	DefaultQueryDelay      int    `libconfig:"default_query_delay" json:"default_query_delay"`
	DefaultQueryTimeout    int64  `libconfig:"default_query_timeout" json:"default_query_timeout"`
	HaveCompress           bool   `libconfig:"have_compress" json:"have_compress"`
	PollTimeout            int64  `libconfig:"poll_timeout" json:"poll_timeout"`
	Interfaces             string `libconfig:"interfaces" json:"interfaces"`
	DefaultSchema          string `libconfig:"default_schema" json:"default_schema"`
	StackSize              int64  `libconfig:"stack_size" json:"stack_size"`
	ServerVersion          string `libconfig:"server_version" json:"server_version"`
	ConnectTimeoutServer   int64  `libconfig:"connect_timeout_server" json:"connection_timeout_server"`
	MonitorHistory         int64  `libconfig:"monitor_history" json:"monitor_history"`
	MonitorConnectInterval int64  `libconfig:"monitor_connect_interval" json:"monitor_connect_interval"`
	MonitorPingInterval    int64  `libconfig:"monitor_ping_interval" json:"monitor_ping_interval"`
	PingInternalServerMsec int64  `libconfig:"ping_internal_server_msec" json:"ping_internal_server_msec"`
	PingTimeoutServer      int    `libconfig:"ping_timeout_server" json:"ping_timeout_server"`
	CommandsStats          bool   `libconfig:"command_stats" json:"command_stats"`
	SessionsSort           bool   `libconfig:"sessions_sort" json:"sessions_sort"`
	MonitorUsername        string `libconfig:"monitor_username" json:"monitor_username"`
	MonitorPassword        string `libconfig:"monitor_password" json:"monitor_password"`
	SSLP2SCert             string `libconfig:"ssl_p2s_cert" json:"ssl_p2s_cert"`
	SSLP2SKey              string `libconfig:"ssl_p2s_key" json:"ssl_p2s_key"`
	SSLP2SCA               string `libconfig:"ssl_p2s_ca" json:"ssl_p2s_ca"`
}

type DatabaseHost struct {
	Name            string
	IpAddress       string
	PublicIPAddress string
}

func NewProxySqlConfig() *ProxySqlConfig {
	return &ProxySqlConfig{}
}

// TODO: Get this from a file
func (psql *ProxySqlConfig) InitDefaults() {

	server1 := ProxySqlMySqlServer{
		Address:        "10.46.0.2",
		Port:           3306,
		Hostgroup:      5,
		MaxConnections: 100,
		Comment:        "thingiverse_master",
		UseSSL:         0,
	}
	server2 := ProxySqlMySqlServer{
		Address:        "10.46.0.22",
		Port:           3306,
		Hostgroup:      10,
		MaxConnections: 100,
		Comment:        "thingiverse-read-replica-2",
		UseSSL:         0,
	}
	server3 := ProxySqlMySqlServer{
		Address:        "10.46.0.20",
		Port:           3306,
		Hostgroup:      10,
		MaxConnections: 100,
		Comment:        "thingiverse-read-replica-1",
		UseSSL:         0,
	}
	servers := []ProxySqlMySqlServer{server1, server2, server3}

	user1 := ProxySqlMySqlUser{
		Username:         "thingiverse-user",
		Password:         "26369b23cf58e3f0",
		DefaultHostgroup: 10,
		Active:           1,
	}
	users := []ProxySqlMySqlUser{user1}
	rule1 := ProxySqlMySqlQueryRule{
		Username:             "thingiverse-user",
		RuleID:               1,
		Active:               1,
		MatchDigest:          "^SELECT .* FOR UPDATE",
		DestinationHostgroup: 5,
		Apply:                1,
		Comment:              "select for update goes to the writer",
	}
	rule2 := ProxySqlMySqlQueryRule{
		Username:             "thingiverse-user",
		RuleID:               2,
		Active:               1,
		MatchDigest:          "^SELECT",
		DestinationHostgroup: 10,
		Apply:                1,
		Comment:              "selects go to the reader",
	}
	rule3 := ProxySqlMySqlQueryRule{
		Username:             "thingiverse-user",
		RuleID:               3,
		Active:               1,
		MatchDigest:          ".*",
		DestinationHostgroup: 5,
		Apply:                1,
		Comment:              "catch-all to writer",
	}
	rule4 := ProxySqlMySqlQueryRule{
		Username:             "thingiverse-user",
		RuleID:               4,
		Active:               1,
		MatchDigest:          "^DELETE",
		DestinationHostgroup: 5,
		Apply:                1,
		Comment:              "deletes go to writer",
	}

	queryRules := []ProxySqlMySqlQueryRule{rule1, rule2, rule3, rule4}
	psql.DataDir = "/var/lib/proxysql"
	psql.AdminVariables = ProxySqlConfigAdminVariables{
		AdminCredentials: "proxysql-admin:adminpassw0rd",
		MysqlIFaces:      "0.0.0.0:6032",
		RefreshInterval:  2000,
	}
	psql.MysqlVariables = ProxySqlConfigMysqlVariables{
		Threads:                4,
		MaxConnections:         2048,
		DefaultQueryDelay:      0,
		DefaultQueryTimeout:    36000000,
		HaveCompress:           true,
		PollTimeout:            2000,
		Interfaces:             "0.0.0.0:6033;/tmp/proxysql.sock",
		DefaultSchema:          "information_schema",
		StackSize:              1048576,
		ServerVersion:          "5.1.30",
		ConnectTimeoutServer:   10000,
		MonitorHistory:         60000,
		MonitorConnectInterval: 200000,
		MonitorPingInterval:    200000,
		PingInternalServerMsec: 10000,
		PingTimeoutServer:      200,
		CommandsStats:          true,
		SessionsSort:           true,
		MonitorUsername:        "proxysql",
		MonitorPassword:        "proxysqlpassw0rd",
	}
	psql.ReadHostGroup = 10
	psql.WriteHostGroup = 5
	psql.MySqlQueryRules = queryRules
	psql.MySqlServers = servers
	psql.MySqlUsers = users
}

func (psql *ProxySqlConfig) MarshallJSON() []byte {
	b, _ := json.MarshalIndent(psql, "", "  ")
	return b
}

// TODO: GCP uses 1:1 for ssl and replica, SSL won't work
//  with proxysql. I have an issue open with them to fix
//  this, or I'll do it myself
//  https://github.com/sysown/proxysql/issues/3331
func (psql *ProxySqlConfig) ToLibConfig() ([]byte, error) {
	te, err := template.New("psql").Parse(`
datadir="{{ .DataDir }}"
admin_variables=
{
  admin_credentials="{{ .AdminVariables.AdminCredentials }}"
  mysql_ifaces="{{ .AdminVariables.MysqlIFaces }}"
  refresh_interval={{ .AdminVariables.RefreshInterval }}
}
mysql_variables=
{
  threads={{ .MysqlVariables.Threads }}
  max_connections={{ .MysqlVariables.MaxConnections }}
  default_query_delay={{ .MysqlVariables.DefaultQueryDelay }}
  default_query_timeout={{ .MysqlVariables.DefaultQueryTimeout }}
  have_compress={{ .MysqlVariables.HaveCompress }}
  poll_timeout={{ .MysqlVariables.PollTimeout }}
  interfaces="{{ .MysqlVariables.Interfaces }}"
  default_schema="{{ .MysqlVariables.DefaultSchema }}"
  stacksize={{ .MysqlVariables.StackSize }}
  server_version="{{ .MysqlVariables.ServerVersion }}"
  connect_timeout_server={{ .MysqlVariables.ConnectTimeoutServer }}
  monitor_history={{ .MysqlVariables.MonitorHistory }}
  monitor_connect_interval={{ .MysqlVariables.MonitorConnectInterval }}
  monitor_ping_interval={{ .MysqlVariables.MonitorPingInterval }}
  ping_interval_server_msec={{ .MysqlVariables.PingInternalServerMsec }}
  ping_timeout_server={{ .MysqlVariables.PingTimeoutServer }}
  commands_stats={{ .MysqlVariables.CommandsStats }}
  sessions_sort={{ .MysqlVariables.SessionsSort }}
  monitor_username="{{ .MysqlVariables.MonitorUsername }}"
  monitor_password="{{ .MysqlVariables.MonitorPassword }}"
  ssl_p2s_cert="{{ .MysqlVariables.SSLP2SCert }}"
  ssl_p2s_key="{{ .MysqlVariables.SSLP2SKey }}"
  ssl_p2s_ca="{{ .MysqlVariables.SSLP2SCA }}"
}
mysql_servers=
(
  {{range $key, $value := .MySqlServers }}{{ if $key }},
  {{ end }}{ address="{{ $value.Address }}" , port={{ $value.Port }} , hostgroup={{ $value.Hostgroup }}, max_connections={{ $value.MaxConnections }}, use_ssl={{ $value.UseSSL }} }{{end}}
)
mysql_users=
(
  {{range $key, $value := .MySqlUsers }}{{ if $key }},
  {{ end }}{ username = "{{ $value.Username }}" , password = "{{ $value.Password }}" , default_hostgroup = {{ $value.DefaultHostgroup }} , active = {{ $value.Active }} }{{end}}
)
mysql_query_rules=
(
  {{range $key, $value :=  .MySqlQueryRules }}{{ if $key }},
  {{ end }}{ rule_id = "{{ $value.RuleID }}" , username="{{ $value.Username }}" , active={{ $value.Active }} , match_digest="{{ $value.MatchDigest }}" , destination_hostgroup={{ .DestinationHostgroup }} , apply={{ $value.Apply }}, comment="{{ $value.Comment }}" }{{end}}
)`)
	if err != nil {
		return nil, err
	}
	output := new(bytes.Buffer)
	err = te.Execute(output, psql)
	if err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

func (psql *ProxySqlConfig) AddReadReplica(readReplica ProxySqlMySqlServer) {
	proxySqlServers := psql.MySqlServers
	proxySqlServers = append(proxySqlServers, readReplica)
	psql.MySqlServers = proxySqlServers
}

type AddDatabaseRequest struct {
	Action         string                                  `json:"action"`
	InstanceName   string                                  `json:"instance_name"`
	Username       string                                  `json:"username"`
	Password       string                                  `json:"password"`
	MasterInstance AddDatabaseRequestDatabaseInformation   `json:"master_instance"`
	ReadReplicas   []AddDatabaseRequestDatabaseInformation `json:"read_replicas"`
	QueryRules     []ProxySqlMySqlQueryRule                `json:"query_rules,omitempty"`
	// these next three will be used once proxysql updates to have instance:ssl config
	KeyData  string `json:"key_data"`
	CertData string `json:"cert_data"`
	CAData   string `json:"ca_data"`
	// binary bool, 0 = false, 1 true
	EnableSSL int `json:"enable_ssl"`
}

type AddDatabaseRequestDatabaseInformation struct {
	Name      string `json:"name"`
	IPAddress string `json:"ip_address"`
}

type AddDatabaseResponse struct {
	Action         string                   `json:"action"`
	QueryRules     []ProxySqlMySqlQueryRule `json:"query_rules"`
	InstanceName   string                   `json:"instance_name"`
	Username       string                   `json:"username"`
	Password       string                   `json:"password"`
	WriteHostGroup int                      `json:"write_host_group"`
	ReadHostGroup  int                      `json:"read_host_group"`
	SSLEnabled     int                      `json:"ssl_enabled"`
}

type RemoveDatabaseRequest struct {
	Action       string `json:"action"`
	InstanceName string `json:"instance_name"`
	Username     string `json:"username"`
}

type ModifyDatabaseRequest struct {
	Action           string                   `json:"action"`
	InstanceName     string                   `json:"instance_name"`
	Username         string                   `json:"username"`
	AddQueryRules    []ProxySqlMySqlQueryRule `json:"add_query_rules"`
	RemoveQueryRules []int                    `json:"remove_query_rules"`
}

type ModifyUserRequest struct {
	Action           string `json:"action"`
	Username         string `json:"username"`
	NewUsername      string `json:"new_username,omitempty"`
	Password         string `json:"password,omitempty"`
	InstanceGroup    string `json:"instance_group,omitempty"`
	DefaultHostgroup int    `json:"default_host_group,omitempty"`
}

type InstanceData struct {
	InstanceName   string                                  `json:"instance_name"`
	ReadHostGroup  int                                     `json:"read_hostgroup"`
	WriteHostGroup int                                     `json:"write_hostgroup"`
	Username       string                                  `json:"username"`
	Password       string                                  `json:"password"`
	QueryRules     []ProxySqlMySqlQueryRule                `json:"query_rules"`
	MasterInstance AddDatabaseRequestDatabaseInformation   `json:"master_instance"`
	ReadReplicas   []AddDatabaseRequestDatabaseInformation `json:"read_replicas"`
	UseSSL         int                                     `json:"use_ssl"`
}

func TriggerScaling(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()
	projectID := os.Getenv("PROJECT_ID")
	secretID := os.Getenv("SECRET_ID")
	authEnabled := os.Getenv("AUTH_ENABLED")
	if authEnabled == "true" {
		secretVersionFull := fmt.Sprintf("projects/%s/secrets/%s/versions/latest", projectID, secretID)
		accessVersionRequest := &secretmanagerpb.AccessSecretVersionRequest{Name: secretVersionFull}
		c, err := secretmanager.NewClient(ctx)
		accessVersionResponse, err := c.AccessSecretVersion(ctx, accessVersionRequest)
		if err != nil {
			log.Println("Getting Secret Version Error:", err.Error())
			w.WriteHeader(500)
			return
		}
		authToken := r.URL.Query().Get("auth_token")
		if string(accessVersionResponse.Payload.Data) != authToken {
			log.Println("Bad auth token:", authToken)
			w.WriteHeader(401)
			return
		}
	}

	dsClient, err := datastore.NewClient(ctx, projectID)
	if err != nil {
		log.Println("Failed to create datastore client:", err.Error())
		w.WriteHeader(500)
		return
	}
	psClient, err := pubsub.NewClient(ctx, projectID)
	if err != nil {
		log.Println("Failed to create pubsub client:", err.Error())
		w.WriteHeader(500)
		return
	}
	incidentRequest := IncidentRequest{}
	err = json.NewDecoder(r.Body).Decode(&incidentRequest)
	if err != nil {
		log.Println("Failed to decode body")
		w.WriteHeader(500)
		return
	}
	md := InicidentMetaData{}

	err = json.Unmarshal([]byte(incidentRequest.Incident.Documentation.Content), &md)
	if err != nil {
		log.Println("Failed to unmarshal:", err.Error())
		w.WriteHeader(500)
		return
	}
	dsd := DataStoreDocumentation{
		Content:  incidentRequest.Incident.Documentation.Content,
		MimeType: incidentRequest.Incident.Documentation.MimeType,
	}
	incidentRequest.Incident.ReplicaBaseName = md.ReplicaBaseName
	incidentRequest.Incident.SqlMasterInstance = md.SqlMasterInstance
	key := datastore.NameKey("incident", strings.Replace(incidentRequest.Incident.IncidentID, ".", "-", -1), nil)
	key.Namespace = "chester"
	incidentRequest.Incident.IncidentID = strings.Replace(incidentRequest.Incident.IncidentID, ".", "-", -1)
	dsi := &DataStoreIncident{
		Documentation:     dsd,
		IncidentID:        incidentRequest.Incident.IncidentID,
		PolicyName:        incidentRequest.Incident.PolicyName,
		State:             incidentRequest.Incident.State,
		StartedAt:         incidentRequest.Incident.StartedAt,
		ClosedTimestamp:   incidentRequest.Incident.ClosedTimestamp,
		ReplicaBaseName:   incidentRequest.Incident.ReplicaBaseName,
		SqlMasterInstance: incidentRequest.Incident.SqlMasterInstance,
		Action:            md.Action,
		LastProcess:       GCFPush,
		LastUpdatedBy:     "chester-gcf",
	}
	_, err = dsClient.Put(ctx, key, dsi)
	if err != nil {
		log.Println("Failed to put datastore incident:", err.Error())
		w.WriteHeader(500)
		return
	}
	dataBytes, err := json.Marshal(dsi)
	if err != nil {
		log.Println("Failed to marshal datastore incident:", err.Error())
		w.WriteHeader(500)
		return
	}
	topic := psClient.Topic(os.Getenv("TOPIC"))
	topic.Publish(ctx, &pubsub.Message{
		Data: dataBytes,
	})
	w.WriteHeader(200)
	return
}
