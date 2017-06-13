// Package bigquerydatatransfer provides access to the BigQuery Data Transfer Service API.
//
// See https://cloud.google.com/bigquery/
//
// Usage example:
//
//   import "google.golang.org/api/bigquerydatatransfer/v1"
//   ...
//   bigquerydatatransferService, err := bigquerydatatransfer.New(oauthHttpClient)
package bigquerydatatransfer // import "google.golang.org/api/bigquerydatatransfer/v1"

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	context "golang.org/x/net/context"
	ctxhttp "golang.org/x/net/context/ctxhttp"
	gensupport "google.golang.org/api/gensupport"
	googleapi "google.golang.org/api/googleapi"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// Always reference these packages, just in case the auto-generated code
// below doesn't.
var _ = bytes.NewBuffer
var _ = strconv.Itoa
var _ = fmt.Sprintf
var _ = json.NewDecoder
var _ = io.Copy
var _ = url.Parse
var _ = gensupport.MarshalJSON
var _ = googleapi.Version
var _ = errors.New
var _ = strings.Replace
var _ = context.Canceled
var _ = ctxhttp.Do

const apiId = "bigquerydatatransfer:v1"
const apiName = "bigquerydatatransfer"
const apiVersion = "v1"
const basePath = "https://bigquerydatatransfer.googleapis.com/"

// OAuth2 scopes used by this API.
const (
	// View and manage your data in Google BigQuery
	BigqueryScope = "https://www.googleapis.com/auth/bigquery"
)

func New(client *http.Client) (*Service, error) {
	if client == nil {
		return nil, errors.New("client is nil")
	}
	s := &Service{client: client, BasePath: basePath}
	s.Projects = NewProjectsService(s)
	return s, nil
}

type Service struct {
	client    *http.Client
	BasePath  string // API endpoint base URL
	UserAgent string // optional additional User-Agent fragment

	Projects *ProjectsService
}

func (s *Service) userAgent() string {
	if s.UserAgent == "" {
		return googleapi.UserAgent
	}
	return googleapi.UserAgent + " " + s.UserAgent
}

func NewProjectsService(s *Service) *ProjectsService {
	rs := &ProjectsService{s: s}
	rs.DataSources = NewProjectsDataSourcesService(s)
	rs.TransferConfigs = NewProjectsTransferConfigsService(s)
	return rs
}

type ProjectsService struct {
	s *Service

	DataSources *ProjectsDataSourcesService

	TransferConfigs *ProjectsTransferConfigsService
}

func NewProjectsDataSourcesService(s *Service) *ProjectsDataSourcesService {
	rs := &ProjectsDataSourcesService{s: s}
	return rs
}

type ProjectsDataSourcesService struct {
	s *Service
}

func NewProjectsTransferConfigsService(s *Service) *ProjectsTransferConfigsService {
	rs := &ProjectsTransferConfigsService{s: s}
	rs.Runs = NewProjectsTransferConfigsRunsService(s)
	return rs
}

type ProjectsTransferConfigsService struct {
	s *Service

	Runs *ProjectsTransferConfigsRunsService
}

func NewProjectsTransferConfigsRunsService(s *Service) *ProjectsTransferConfigsRunsService {
	rs := &ProjectsTransferConfigsRunsService{s: s}
	rs.TransferLogs = NewProjectsTransferConfigsRunsTransferLogsService(s)
	return rs
}

type ProjectsTransferConfigsRunsService struct {
	s *Service

	TransferLogs *ProjectsTransferConfigsRunsTransferLogsService
}

func NewProjectsTransferConfigsRunsTransferLogsService(s *Service) *ProjectsTransferConfigsRunsTransferLogsService {
	rs := &ProjectsTransferConfigsRunsTransferLogsService{s: s}
	return rs
}

type ProjectsTransferConfigsRunsTransferLogsService struct {
	s *Service
}

// CheckValidCredsRequest: A request to determine whether the user has
// valid credentials. This method
// is used to limit the number of OAuth popups in the user interface.
// The
// user id is inferred from the API call context.
// If the data source has the Google+ authorization type, this
// method
// returns false, as it cannot be determined whether the credentials
// are
// already valid merely based on the user id.
type CheckValidCredsRequest struct {
}

// CheckValidCredsResponse: A response indicating whether the
// credentials exist and are valid.
type CheckValidCredsResponse struct {
	// HasValidCreds: If set to `true`, the credentials exist and are valid.
	HasValidCreds bool `json:"hasValidCreds,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "HasValidCreds") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`

	// NullFields is a list of field names (e.g. "HasValidCreds") to include
	// in API requests with the JSON null value. By default, fields with
	// empty values are omitted from API requests. However, any field with
	// an empty value appearing in NullFields will be sent to the server as
	// null. It is an error if a field in this list has a non-empty value.
	// This may be used to include null fields in Patch requests.
	NullFields []string `json:"-"`
}

func (s *CheckValidCredsResponse) MarshalJSON() ([]byte, error) {
	type noMethod CheckValidCredsResponse
	raw := noMethod(*s)
	return gensupport.MarshalJSON(raw, s.ForceSendFields, s.NullFields)
}

// DataSource: Represents data source metadata. Metadata is sufficient
// to
// render UI and request proper OAuth tokens.
type DataSource struct {
	// AuthorizationType: Indicates the type of authorization.
	//
	// Possible values:
	//   "AUTHORIZATION_TYPE_UNSPECIFIED" - Type unspecified.
	//   "AUTHORIZATION_CODE" - Use OAuth 2 authorization codes that can be
	// exchanged
	// for a refresh token on the backend.
	//   "GOOGLE_PLUS_AUTHORIZATION_CODE" - Return an authorization code for
	// a given Google+ page that can then be
	// exchanged for a refresh token on the backend.
	AuthorizationType string `json:"authorizationType,omitempty"`

	// ClientId: Data source client id which should be used to receive
	// refresh token.
	// When not supplied, no offline credentials are populated for data
	// transfer.
	ClientId string `json:"clientId,omitempty"`

	// DataRefreshType: Specifies whether the data source supports automatic
	// data refresh for the
	// past few days, and how it's supported.
	// For some data sources, data might not be complete until a few days
	// later,
	// so it's useful to refresh data automatically.
	//
	// Possible values:
	//   "NONE" - The data source won't support data auto refresh, which is
	// default value.
	//   "SLIDING_WINDOW" - The data source supports data auto refresh, and
	// runs will be scheduled
	// for the past few days. Does not allow custom values to be set for
	// each
	// transfer config.
	//   "CUSTOM_SLIDING_WINDOW" - The data source supports data auto
	// refresh, and runs will be scheduled
	// for the past few days. Allows custom values to be set for each
	// transfer
	// config.
	DataRefreshType string `json:"dataRefreshType,omitempty"`

	// DataSourceId: Data source id.
	DataSourceId string `json:"dataSourceId,omitempty"`

	// DefaultDataRefreshWindowDays: Default data refresh window on
	// days.
	// Only meaningful when `data_refresh_type` = `SLIDING_WINDOW`.
	DefaultDataRefreshWindowDays int64 `json:"defaultDataRefreshWindowDays,omitempty"`

	// DefaultSchedule: Default data transfer schedule.
	// Examples of valid schedules include:
	// `1st,3rd monday of month 15:30`,
	// `every wed,fri of jan,jun 13:15`, and
	// `first sunday of quarter 00:00`.
	DefaultSchedule string `json:"defaultSchedule,omitempty"`

	// Description: User friendly data source description string.
	Description string `json:"description,omitempty"`

	// DisplayName: User friendly data source name.
	DisplayName string `json:"displayName,omitempty"`

	// HelpUrl: Url for the help document for this data source.
	HelpUrl string `json:"helpUrl,omitempty"`

	// ManualRunsDisabled: Disables backfilling and manual run
	// scheduling
	// for the data source.
	ManualRunsDisabled bool `json:"manualRunsDisabled,omitempty"`

	// Name: Data source resource name.
	Name string `json:"name,omitempty"`

	// Parameters: Data source parameters.
	Parameters []*DataSourceParameter `json:"parameters,omitempty"`

	// Scopes: Api auth scopes for which refresh token needs to be obtained.
	// Only valid
	// when `client_id` is specified. Ignored otherwise. These are scopes
	// needed
	// by a data source to prepare data and ingest them into BigQuery,
	// e.g., https://www.googleapis.com/auth/bigquery
	Scopes []string `json:"scopes,omitempty"`

	// StatusUpdateDeadlineSeconds: The number of seconds to wait for a
	// status update from the data source
	// before BigQuery marks the transfer as failed.
	StatusUpdateDeadlineSeconds int64 `json:"statusUpdateDeadlineSeconds,omitempty"`

	// SupportsCustomSchedule: Specifies whether the data source supports a
	// user defined schedule, or
	// operates on the default schedule.
	// When set to `true`, user can override default schedule.
	SupportsCustomSchedule bool `json:"supportsCustomSchedule,omitempty"`

	// SupportsMultipleTransfers: Indicates whether the data source supports
	// multiple transfers
	// to different BigQuery targets.
	SupportsMultipleTransfers bool `json:"supportsMultipleTransfers,omitempty"`

	// TransferType: Transfer type. Currently supports only batch
	// transfers,
	// which are transfers that use the BigQuery batch APIs (load or
	// query) to ingest the data.
	//
	// Possible values:
	//   "TRANSFER_TYPE_UNSPECIFIED" - Invalid or Unknown transfer type
	// placeholder.
	//   "BATCH" - Batch data transfer.
	//   "STREAMING" - Streaming data transfer. Streaming data source
	// currently doesn't
	// support multiple transfer configs per project.
	TransferType string `json:"transferType,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "AuthorizationType")
	// to unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`

	// NullFields is a list of field names (e.g. "AuthorizationType") to
	// include in API requests with the JSON null value. By default, fields
	// with empty values are omitted from API requests. However, any field
	// with an empty value appearing in NullFields will be sent to the
	// server as null. It is an error if a field in this list has a
	// non-empty value. This may be used to include null fields in Patch
	// requests.
	NullFields []string `json:"-"`
}

func (s *DataSource) MarshalJSON() ([]byte, error) {
	type noMethod DataSource
	raw := noMethod(*s)
	return gensupport.MarshalJSON(raw, s.ForceSendFields, s.NullFields)
}

// DataSourceParameter: Represents a data source parameter with
// validation rules, so that
// parameters can be rendered in the UI. These parameters are given to
// us by
// supported data sources, and include all needed information for
// rendering
// and validation.
// Thus, whoever uses this api can decide to generate either generic
// ui,
// or custom data source specific forms.
type DataSourceParameter struct {
	// AllowedValues: All possible values for the parameter.
	AllowedValues []string `json:"allowedValues,omitempty"`

	// Description: Parameter description.
	Description string `json:"description,omitempty"`

	// DisplayName: Parameter display name in the user interface.
	DisplayName string `json:"displayName,omitempty"`

	// Fields: When parameter is a record, describes child fields.
	Fields []*DataSourceParameter `json:"fields,omitempty"`

	// Immutable: Cannot be changed after initial creation.
	Immutable bool `json:"immutable,omitempty"`

	// MaxValue: For integer and double values specifies maxminum allowed
	// value.
	MaxValue float64 `json:"maxValue,omitempty"`

	// MinValue: For integer and double values specifies minimum allowed
	// value.
	MinValue float64 `json:"minValue,omitempty"`

	// ParamId: Parameter identifier.
	ParamId string `json:"paramId,omitempty"`

	// Recurse: If set to true, schema should be taken from the parent with
	// the same
	// parameter_id. Only applicable when parameter type is RECORD.
	Recurse bool `json:"recurse,omitempty"`

	// Repeated: Can parameter have multiple values.
	Repeated bool `json:"repeated,omitempty"`

	// Required: Is parameter required.
	Required bool `json:"required,omitempty"`

	// Type: Parameter type.
	//
	// Possible values:
	//   "TYPE_UNSPECIFIED" - Type unspecified.
	//   "STRING" - String parameter.
	//   "INTEGER" - Integer parameter (64-bits).
	// Will be serialized to json as string.
	//   "DOUBLE" - Double precision floating point parameter.
	//   "BOOLEAN" - Boolean parameter.
	//   "RECORD" - Record parameter.
	//   "PLUS_PAGE" - Page ID for a Google+ Page.
	Type string `json:"type,omitempty"`

	// ValidationDescription: Description of the requirements for this
	// field, in case the user input does
	// not fulfill the regex pattern or min/max values.
	ValidationDescription string `json:"validationDescription,omitempty"`

	// ValidationHelpUrl: URL to a help document to further explain the
	// naming requirements.
	ValidationHelpUrl string `json:"validationHelpUrl,omitempty"`

	// ValidationRegex: Regular expression which can be used for parameter
	// validation.
	ValidationRegex string `json:"validationRegex,omitempty"`

	// ForceSendFields is a list of field names (e.g. "AllowedValues") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`

	// NullFields is a list of field names (e.g. "AllowedValues") to include
	// in API requests with the JSON null value. By default, fields with
	// empty values are omitted from API requests. However, any field with
	// an empty value appearing in NullFields will be sent to the server as
	// null. It is an error if a field in this list has a non-empty value.
	// This may be used to include null fields in Patch requests.
	NullFields []string `json:"-"`
}

func (s *DataSourceParameter) MarshalJSON() ([]byte, error) {
	type noMethod DataSourceParameter
	raw := noMethod(*s)
	return gensupport.MarshalJSON(raw, s.ForceSendFields, s.NullFields)
}

func (s *DataSourceParameter) UnmarshalJSON(data []byte) error {
	type noMethod DataSourceParameter
	var s1 struct {
		MaxValue gensupport.JSONFloat64 `json:"maxValue"`
		MinValue gensupport.JSONFloat64 `json:"minValue"`
		*noMethod
	}
	s1.noMethod = (*noMethod)(s)
	if err := json.Unmarshal(data, &s1); err != nil {
		return err
	}
	s.MaxValue = float64(s1.MaxValue)
	s.MinValue = float64(s1.MinValue)
	return nil
}

// Empty: A generic empty message that you can re-use to avoid defining
// duplicated
// empty messages in your APIs. A typical example is to use it as the
// request
// or the response type of an API method. For instance:
//
//     service Foo {
//       rpc Bar(google.protobuf.Empty) returns
// (google.protobuf.Empty);
//     }
//
// The JSON representation for `Empty` is empty JSON object `{}`.
type Empty struct {
	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`
}

// IsEnabledRequest: A request to determine whether data transfer is
// enabled for the project.
type IsEnabledRequest struct {
}

// IsEnabledResponse: A response to indicate whether data transfer is
// enabled for the project.
type IsEnabledResponse struct {
	// Enabled: Indicates whether the project is enabled.
	Enabled bool `json:"enabled,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "Enabled") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`

	// NullFields is a list of field names (e.g. "Enabled") to include in
	// API requests with the JSON null value. By default, fields with empty
	// values are omitted from API requests. However, any field with an
	// empty value appearing in NullFields will be sent to the server as
	// null. It is an error if a field in this list has a non-empty value.
	// This may be used to include null fields in Patch requests.
	NullFields []string `json:"-"`
}

func (s *IsEnabledResponse) MarshalJSON() ([]byte, error) {
	type noMethod IsEnabledResponse
	raw := noMethod(*s)
	return gensupport.MarshalJSON(raw, s.ForceSendFields, s.NullFields)
}

// ListDataSourcesResponse: Returns list of supported data sources and
// their metadata.
type ListDataSourcesResponse struct {
	// DataSources: List of supported data sources and their transfer
	// settings.
	DataSources []*DataSource `json:"dataSources,omitempty"`

	// NextPageToken: The next-pagination token. For multiple-page list
	// results,
	// this token can be used as the
	// `ListDataSourcesRequest.page_token`
	// to request the next page of list results.
	// @OutputOnly
	NextPageToken string `json:"nextPageToken,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "DataSources") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`

	// NullFields is a list of field names (e.g. "DataSources") to include
	// in API requests with the JSON null value. By default, fields with
	// empty values are omitted from API requests. However, any field with
	// an empty value appearing in NullFields will be sent to the server as
	// null. It is an error if a field in this list has a non-empty value.
	// This may be used to include null fields in Patch requests.
	NullFields []string `json:"-"`
}

func (s *ListDataSourcesResponse) MarshalJSON() ([]byte, error) {
	type noMethod ListDataSourcesResponse
	raw := noMethod(*s)
	return gensupport.MarshalJSON(raw, s.ForceSendFields, s.NullFields)
}

// ListTransferConfigsResponse: The returned list of pipelines in the
// project.
type ListTransferConfigsResponse struct {
	// NextPageToken: The next-pagination token. For multiple-page list
	// results,
	// this token can be used as
	// the
	// `ListTransferConfigsRequest.page_token`
	// to request the next page of list results.
	// @OutputOnly
	NextPageToken string `json:"nextPageToken,omitempty"`

	// TransferConfigs: The stored pipeline transfer
	// configurations.
	// @OutputOnly
	TransferConfigs []*TransferConfig `json:"transferConfigs,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "NextPageToken") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`

	// NullFields is a list of field names (e.g. "NextPageToken") to include
	// in API requests with the JSON null value. By default, fields with
	// empty values are omitted from API requests. However, any field with
	// an empty value appearing in NullFields will be sent to the server as
	// null. It is an error if a field in this list has a non-empty value.
	// This may be used to include null fields in Patch requests.
	NullFields []string `json:"-"`
}

func (s *ListTransferConfigsResponse) MarshalJSON() ([]byte, error) {
	type noMethod ListTransferConfigsResponse
	raw := noMethod(*s)
	return gensupport.MarshalJSON(raw, s.ForceSendFields, s.NullFields)
}

// ListTransferLogsResponse: The returned list transfer run messages.
type ListTransferLogsResponse struct {
	// NextPageToken: The next-pagination token. For multiple-page list
	// results,
	// this token can be used as
	// the
	// `GetTransferRunLogRequest.page_token`
	// to request the next page of list results.
	// @OutputOnly
	NextPageToken string `json:"nextPageToken,omitempty"`

	// TransferMessages: The stored pipeline transfer messages.
	// @OutputOnly
	TransferMessages []*TransferMessage `json:"transferMessages,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "NextPageToken") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`

	// NullFields is a list of field names (e.g. "NextPageToken") to include
	// in API requests with the JSON null value. By default, fields with
	// empty values are omitted from API requests. However, any field with
	// an empty value appearing in NullFields will be sent to the server as
	// null. It is an error if a field in this list has a non-empty value.
	// This may be used to include null fields in Patch requests.
	NullFields []string `json:"-"`
}

func (s *ListTransferLogsResponse) MarshalJSON() ([]byte, error) {
	type noMethod ListTransferLogsResponse
	raw := noMethod(*s)
	return gensupport.MarshalJSON(raw, s.ForceSendFields, s.NullFields)
}

// ListTransferRunsResponse: The returned list of pipelines in the
// project.
type ListTransferRunsResponse struct {
	// NextPageToken: The next-pagination token. For multiple-page list
	// results,
	// this token can be used as the
	// `ListTransferRunsRequest.page_token`
	// to request the next page of list results.
	// @OutputOnly
	NextPageToken string `json:"nextPageToken,omitempty"`

	// TransferRuns: The stored pipeline transfer runs.
	// @OutputOnly
	TransferRuns []*TransferRun `json:"transferRuns,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "NextPageToken") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`

	// NullFields is a list of field names (e.g. "NextPageToken") to include
	// in API requests with the JSON null value. By default, fields with
	// empty values are omitted from API requests. However, any field with
	// an empty value appearing in NullFields will be sent to the server as
	// null. It is an error if a field in this list has a non-empty value.
	// This may be used to include null fields in Patch requests.
	NullFields []string `json:"-"`
}

func (s *ListTransferRunsResponse) MarshalJSON() ([]byte, error) {
	type noMethod ListTransferRunsResponse
	raw := noMethod(*s)
	return gensupport.MarshalJSON(raw, s.ForceSendFields, s.NullFields)
}

// ScheduleTransferRunsRequest: A request to schedule transfer runs for
// a time range.
type ScheduleTransferRunsRequest struct {
	// RangeEndTime: End time of the range of transfer runs.
	RangeEndTime string `json:"rangeEndTime,omitempty"`

	// RangeStartTime: Start time of the range of transfer runs.
	RangeStartTime string `json:"rangeStartTime,omitempty"`

	// ForceSendFields is a list of field names (e.g. "RangeEndTime") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`

	// NullFields is a list of field names (e.g. "RangeEndTime") to include
	// in API requests with the JSON null value. By default, fields with
	// empty values are omitted from API requests. However, any field with
	// an empty value appearing in NullFields will be sent to the server as
	// null. It is an error if a field in this list has a non-empty value.
	// This may be used to include null fields in Patch requests.
	NullFields []string `json:"-"`
}

func (s *ScheduleTransferRunsRequest) MarshalJSON() ([]byte, error) {
	type noMethod ScheduleTransferRunsRequest
	raw := noMethod(*s)
	return gensupport.MarshalJSON(raw, s.ForceSendFields, s.NullFields)
}

// ScheduleTransferRunsResponse: A response to schedule transfer runs
// for a time range.
type ScheduleTransferRunsResponse struct {
	// CreatedRuns: The transfer runs that were created.
	CreatedRuns []*TransferRun `json:"createdRuns,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "CreatedRuns") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`

	// NullFields is a list of field names (e.g. "CreatedRuns") to include
	// in API requests with the JSON null value. By default, fields with
	// empty values are omitted from API requests. However, any field with
	// an empty value appearing in NullFields will be sent to the server as
	// null. It is an error if a field in this list has a non-empty value.
	// This may be used to include null fields in Patch requests.
	NullFields []string `json:"-"`
}

func (s *ScheduleTransferRunsResponse) MarshalJSON() ([]byte, error) {
	type noMethod ScheduleTransferRunsResponse
	raw := noMethod(*s)
	return gensupport.MarshalJSON(raw, s.ForceSendFields, s.NullFields)
}

// SetEnabledRequest: A request to set whether data transfer is enabled
// or disabled for a project.
type SetEnabledRequest struct {
	// Enabled: Whether data transfer should be enabled or disabled for the
	// project.
	Enabled bool `json:"enabled,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Enabled") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`

	// NullFields is a list of field names (e.g. "Enabled") to include in
	// API requests with the JSON null value. By default, fields with empty
	// values are omitted from API requests. However, any field with an
	// empty value appearing in NullFields will be sent to the server as
	// null. It is an error if a field in this list has a non-empty value.
	// This may be used to include null fields in Patch requests.
	NullFields []string `json:"-"`
}

func (s *SetEnabledRequest) MarshalJSON() ([]byte, error) {
	type noMethod SetEnabledRequest
	raw := noMethod(*s)
	return gensupport.MarshalJSON(raw, s.ForceSendFields, s.NullFields)
}

// TransferConfig: Represents a data transfer configuration. A transfer
// configuration
// contains all metadata needed to perform a data transfer. For
// example,
// `destination_dataset_id` specifies where data should be stored.
// When a new transfer configuration is created, the
// specified
// `destination_dataset_id` is created when needed and shared with
// the
// appropriate data source service account.
type TransferConfig struct {
	// DataRefreshWindowDays: The number of days to look back to
	// automatically refresh the data.
	// For example, if `data_refresh_window_days = 10`, then every
	// day
	// BigQuery reingests data for [today-10, today-1], rather than
	// ingesting data
	// for just [today-1].
	// Only valid if the data source supports the feature. Set the value to
	// 0
	// to use the default value.
	DataRefreshWindowDays int64 `json:"dataRefreshWindowDays,omitempty"`

	// DataSourceId: Data source id. Cannot be changed once data transfer is
	// created.
	DataSourceId string `json:"dataSourceId,omitempty"`

	// DestinationDatasetId: The BigQuery target dataset id.
	DestinationDatasetId string `json:"destinationDatasetId,omitempty"`

	// Disabled: Is this config disabled. When set to true, no runs are
	// scheduled
	// for a given transfer.
	Disabled bool `json:"disabled,omitempty"`

	// DisplayName: User specified display name for the data transfer.
	DisplayName string `json:"displayName,omitempty"`

	// Name: The resource name of the transfer run.
	// Transfer run names have the
	// form
	// `projects/{project_id}/transferConfigs/{config_id}`.
	// Where `config_id` is usually a uuid, even though it is not
	// guaranteed or required. The name is ignored when creating a transfer
	// run.
	Name string `json:"name,omitempty"`

	// NextRunTime: Next time when data transfer will run. Output only.
	// Applicable
	// only for batch data transfers.
	// @OutputOnly
	NextRunTime string `json:"nextRunTime,omitempty"`

	// Params: Data transfer specific parameters.
	Params googleapi.RawMessage `json:"params,omitempty"`

	// Schedule: Data transfer schedule in GROC format.
	// If the data source does not support a custom schedule, this should
	// be
	// empty. If it is empty, the default value for the data source will
	// be
	// used.
	// The specified times are in UTC.
	// Examples of valid GROC include:
	// `1st,3rd monday of month 15:30`,
	// `every wed,fri of jan,jun 13:15`, and
	// `first sunday of quarter 00:00`.
	Schedule string `json:"schedule,omitempty"`

	// Status: Status of the most recently updated transfer run.
	// @OutputOnly
	//
	// Possible values:
	//   "TRANSFER_STATUS_UNSPECIFIED" - Status placeholder.
	//   "INACTIVE" - Data transfer is inactive.
	//   "PENDING" - Data transfer is scheduled and is waiting to be picked
	// up by
	// data transfer backend.
	//   "RUNNING" - Data transfer is in progress.
	//   "SUCCEEDED" - Data transfer completed successsfully.
	//   "FAILED" - Data transfer failed.
	//   "CANCELLED" - Data transfer is cancelled.
	Status string `json:"status,omitempty"`

	// UpdateTime: Data transfer modification time. Ignored by server on
	// input.
	// @OutputOnly
	UpdateTime string `json:"updateTime,omitempty"`

	// UserId: GaiaID of the user on whose behalf transfer is done.
	// Applicable only
	// to data sources that do not support service accounts. When set to
	// 0,
	// the data source service account credentials are used.
	// @OutputOnly
	UserId int64 `json:"userId,omitempty,string"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g.
	// "DataRefreshWindowDays") to unconditionally include in API requests.
	// By default, fields with empty values are omitted from API requests.
	// However, any non-pointer, non-interface field appearing in
	// ForceSendFields will be sent to the server regardless of whether the
	// field is empty or not. This may be used to include empty fields in
	// Patch requests.
	ForceSendFields []string `json:"-"`

	// NullFields is a list of field names (e.g. "DataRefreshWindowDays") to
	// include in API requests with the JSON null value. By default, fields
	// with empty values are omitted from API requests. However, any field
	// with an empty value appearing in NullFields will be sent to the
	// server as null. It is an error if a field in this list has a
	// non-empty value. This may be used to include null fields in Patch
	// requests.
	NullFields []string `json:"-"`
}

func (s *TransferConfig) MarshalJSON() ([]byte, error) {
	type noMethod TransferConfig
	raw := noMethod(*s)
	return gensupport.MarshalJSON(raw, s.ForceSendFields, s.NullFields)
}

// TransferMessage: Represents a user facing message for a particular
// data transfer run.
type TransferMessage struct {
	// MessageText: Message text.
	MessageText string `json:"messageText,omitempty"`

	// MessageTime: Time when message was logged.
	MessageTime string `json:"messageTime,omitempty"`

	// Severity: Message severity.
	//
	// Possible values:
	//   "MESSAGE_SEVERITY_UNSPECIFIED" - No severity specified.
	//   "INFO" - Informational message.
	//   "WARNING" - Warning message.
	//   "ERROR" - Error message.
	Severity string `json:"severity,omitempty"`

	// ForceSendFields is a list of field names (e.g. "MessageText") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`

	// NullFields is a list of field names (e.g. "MessageText") to include
	// in API requests with the JSON null value. By default, fields with
	// empty values are omitted from API requests. However, any field with
	// an empty value appearing in NullFields will be sent to the server as
	// null. It is an error if a field in this list has a non-empty value.
	// This may be used to include null fields in Patch requests.
	NullFields []string `json:"-"`
}

func (s *TransferMessage) MarshalJSON() ([]byte, error) {
	type noMethod TransferMessage
	raw := noMethod(*s)
	return gensupport.MarshalJSON(raw, s.ForceSendFields, s.NullFields)
}

// TransferRun: Represents a data transfer run.
type TransferRun struct {
	// DataSourceId: Data source id.
	// @OutputOnly
	DataSourceId string `json:"dataSourceId,omitempty"`

	// DestinationDatasetId: The BigQuery target dataset id.
	DestinationDatasetId string `json:"destinationDatasetId,omitempty"`

	// EndTime: Time when transfer run ended. Parameter ignored by server
	// for input
	// requests.
	// @OutputOnly
	EndTime string `json:"endTime,omitempty"`

	// Name: The resource name of the transfer run.
	// Transfer run names have the
	// form
	// `projects/{project_id}/transferConfigs/{config_id}/runs/{run_id}`
	// .
	// The name is ignored when creating a transfer run.
	Name string `json:"name,omitempty"`

	// Params: Data transfer specific parameters.
	Params googleapi.RawMessage `json:"params,omitempty"`

	// RunTime: For batch transfer runs, specifies the date and time
	// that
	// data should be ingested.
	RunTime string `json:"runTime,omitempty"`

	// Schedule: Describes the schedule of this transfer run if it was
	// created as part of
	// a regular schedule. For batch transfer runs that are directly
	// created,
	// this is empty.
	// NOTE: the system might choose to delay the schedule depending on
	// the
	// current load, so `schedule_time` doesn't always matches
	// this.
	// @OutputOnly
	Schedule string `json:"schedule,omitempty"`

	// ScheduleTime: Minimum time after which a transfer run can be started.
	ScheduleTime string `json:"scheduleTime,omitempty"`

	// StartTime: Time when transfer run was started. Parameter ignored by
	// server for input
	// requests.
	// @OutputOnly
	StartTime string `json:"startTime,omitempty"`

	// Status: Data transfer run status. Ignored for input
	// requests.
	// @OutputOnly
	//
	// Possible values:
	//   "TRANSFER_STATUS_UNSPECIFIED" - Status placeholder.
	//   "INACTIVE" - Data transfer is inactive.
	//   "PENDING" - Data transfer is scheduled and is waiting to be picked
	// up by
	// data transfer backend.
	//   "RUNNING" - Data transfer is in progress.
	//   "SUCCEEDED" - Data transfer completed successsfully.
	//   "FAILED" - Data transfer failed.
	//   "CANCELLED" - Data transfer is cancelled.
	Status string `json:"status,omitempty"`

	// UpdateTime: Last time the data transfer run status was
	// updated.
	// @OutputOnly
	UpdateTime string `json:"updateTime,omitempty"`

	// UserId: The user id for this transfer run.
	// @OutputOnly
	UserId int64 `json:"userId,omitempty,string"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "DataSourceId") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`

	// NullFields is a list of field names (e.g. "DataSourceId") to include
	// in API requests with the JSON null value. By default, fields with
	// empty values are omitted from API requests. However, any field with
	// an empty value appearing in NullFields will be sent to the server as
	// null. It is an error if a field in this list has a non-empty value.
	// This may be used to include null fields in Patch requests.
	NullFields []string `json:"-"`
}

func (s *TransferRun) MarshalJSON() ([]byte, error) {
	type noMethod TransferRun
	raw := noMethod(*s)
	return gensupport.MarshalJSON(raw, s.ForceSendFields, s.NullFields)
}

// method id "bigquerydatatransfer.projects.isEnabled":

type ProjectsIsEnabledCall struct {
	s                *Service
	name             string
	isenabledrequest *IsEnabledRequest
	urlParams_       gensupport.URLParams
	ctx_             context.Context
	header_          http.Header
}

// IsEnabled: Returns true if data transfer is enabled for a project.
func (r *ProjectsService) IsEnabled(name string, isenabledrequest *IsEnabledRequest) *ProjectsIsEnabledCall {
	c := &ProjectsIsEnabledCall{s: r.s, urlParams_: make(gensupport.URLParams)}
	c.name = name
	c.isenabledrequest = isenabledrequest
	return c
}

// Fields allows partial responses to be retrieved. See
// https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ProjectsIsEnabledCall) Fields(s ...googleapi.Field) *ProjectsIsEnabledCall {
	c.urlParams_.Set("fields", googleapi.CombineFields(s))
	return c
}

// Context sets the context to be used in this call's Do method. Any
// pending HTTP request will be aborted if the provided context is
// canceled.
func (c *ProjectsIsEnabledCall) Context(ctx context.Context) *ProjectsIsEnabledCall {
	c.ctx_ = ctx
	return c
}

// Header returns an http.Header that can be modified by the caller to
// add HTTP headers to the request.
func (c *ProjectsIsEnabledCall) Header() http.Header {
	if c.header_ == nil {
		c.header_ = make(http.Header)
	}
	return c.header_
}

func (c *ProjectsIsEnabledCall) doRequest(alt string) (*http.Response, error) {
	reqHeaders := make(http.Header)
	for k, v := range c.header_ {
		reqHeaders[k] = v
	}
	reqHeaders.Set("User-Agent", c.s.userAgent())
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.isenabledrequest)
	if err != nil {
		return nil, err
	}
	reqHeaders.Set("Content-Type", "application/json")
	c.urlParams_.Set("alt", alt)
	urls := googleapi.ResolveRelative(c.s.BasePath, "v1/{+name}:isEnabled")
	urls += "?" + c.urlParams_.Encode()
	req, _ := http.NewRequest("POST", urls, body)
	req.Header = reqHeaders
	googleapi.Expand(req.URL, map[string]string{
		"name": c.name,
	})
	return gensupport.SendRequest(c.ctx_, c.s.client, req)
}

// Do executes the "bigquerydatatransfer.projects.isEnabled" call.
// Exactly one of *IsEnabledResponse or error will be non-nil. Any
// non-2xx status code is an error. Response headers are in either
// *IsEnabledResponse.ServerResponse.Header or (if a response was
// returned at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *ProjectsIsEnabledCall) Do(opts ...googleapi.CallOption) (*IsEnabledResponse, error) {
	gensupport.SetOptions(c.urlParams_, opts...)
	res, err := c.doRequest("json")
	if res != nil && res.StatusCode == http.StatusNotModified {
		if res.Body != nil {
			res.Body.Close()
		}
		return nil, &googleapi.Error{
			Code:   res.StatusCode,
			Header: res.Header,
		}
	}
	if err != nil {
		return nil, err
	}
	defer googleapi.CloseBody(res)
	if err := googleapi.CheckResponse(res); err != nil {
		return nil, err
	}
	ret := &IsEnabledResponse{
		ServerResponse: googleapi.ServerResponse{
			Header:         res.Header,
			HTTPStatusCode: res.StatusCode,
		},
	}
	target := &ret
	if err := json.NewDecoder(res.Body).Decode(target); err != nil {
		return nil, err
	}
	return ret, nil
	// {
	//   "description": "Returns true if data transfer is enabled for a project.",
	//   "flatPath": "v1/projects/{projectsId}:isEnabled",
	//   "httpMethod": "POST",
	//   "id": "bigquerydatatransfer.projects.isEnabled",
	//   "parameterOrder": [
	//     "name"
	//   ],
	//   "parameters": {
	//     "name": {
	//       "description": "The name of the project resource in the form:\n`projects/{project_id}`",
	//       "location": "path",
	//       "pattern": "^projects/[^/]+$",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "v1/{+name}:isEnabled",
	//   "request": {
	//     "$ref": "IsEnabledRequest"
	//   },
	//   "response": {
	//     "$ref": "IsEnabledResponse"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/bigquery"
	//   ]
	// }

}

// method id "bigquerydatatransfer.projects.setEnabled":

type ProjectsSetEnabledCall struct {
	s                 *Service
	name              string
	setenabledrequest *SetEnabledRequest
	urlParams_        gensupport.URLParams
	ctx_              context.Context
	header_           http.Header
}

// SetEnabled: Enables or disables data transfer for a project.
// This
// method requires the additional scope
// of
// 'https://www.googleapis.com/auth/cloudplatformprojects'
// to manage the cloud project permissions.
func (r *ProjectsService) SetEnabled(name string, setenabledrequest *SetEnabledRequest) *ProjectsSetEnabledCall {
	c := &ProjectsSetEnabledCall{s: r.s, urlParams_: make(gensupport.URLParams)}
	c.name = name
	c.setenabledrequest = setenabledrequest
	return c
}

// Fields allows partial responses to be retrieved. See
// https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ProjectsSetEnabledCall) Fields(s ...googleapi.Field) *ProjectsSetEnabledCall {
	c.urlParams_.Set("fields", googleapi.CombineFields(s))
	return c
}

// Context sets the context to be used in this call's Do method. Any
// pending HTTP request will be aborted if the provided context is
// canceled.
func (c *ProjectsSetEnabledCall) Context(ctx context.Context) *ProjectsSetEnabledCall {
	c.ctx_ = ctx
	return c
}

// Header returns an http.Header that can be modified by the caller to
// add HTTP headers to the request.
func (c *ProjectsSetEnabledCall) Header() http.Header {
	if c.header_ == nil {
		c.header_ = make(http.Header)
	}
	return c.header_
}

func (c *ProjectsSetEnabledCall) doRequest(alt string) (*http.Response, error) {
	reqHeaders := make(http.Header)
	for k, v := range c.header_ {
		reqHeaders[k] = v
	}
	reqHeaders.Set("User-Agent", c.s.userAgent())
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.setenabledrequest)
	if err != nil {
		return nil, err
	}
	reqHeaders.Set("Content-Type", "application/json")
	c.urlParams_.Set("alt", alt)
	urls := googleapi.ResolveRelative(c.s.BasePath, "v1/{+name}:setEnabled")
	urls += "?" + c.urlParams_.Encode()
	req, _ := http.NewRequest("POST", urls, body)
	req.Header = reqHeaders
	googleapi.Expand(req.URL, map[string]string{
		"name": c.name,
	})
	return gensupport.SendRequest(c.ctx_, c.s.client, req)
}

// Do executes the "bigquerydatatransfer.projects.setEnabled" call.
// Exactly one of *Empty or error will be non-nil. Any non-2xx status
// code is an error. Response headers are in either
// *Empty.ServerResponse.Header or (if a response was returned at all)
// in error.(*googleapi.Error).Header. Use googleapi.IsNotModified to
// check whether the returned error was because http.StatusNotModified
// was returned.
func (c *ProjectsSetEnabledCall) Do(opts ...googleapi.CallOption) (*Empty, error) {
	gensupport.SetOptions(c.urlParams_, opts...)
	res, err := c.doRequest("json")
	if res != nil && res.StatusCode == http.StatusNotModified {
		if res.Body != nil {
			res.Body.Close()
		}
		return nil, &googleapi.Error{
			Code:   res.StatusCode,
			Header: res.Header,
		}
	}
	if err != nil {
		return nil, err
	}
	defer googleapi.CloseBody(res)
	if err := googleapi.CheckResponse(res); err != nil {
		return nil, err
	}
	ret := &Empty{
		ServerResponse: googleapi.ServerResponse{
			Header:         res.Header,
			HTTPStatusCode: res.StatusCode,
		},
	}
	target := &ret
	if err := json.NewDecoder(res.Body).Decode(target); err != nil {
		return nil, err
	}
	return ret, nil
	// {
	//   "description": "Enables or disables data transfer for a project. This\nmethod requires the additional scope of\n'https://www.googleapis.com/auth/cloudplatformprojects'\nto manage the cloud project permissions.",
	//   "flatPath": "v1/projects/{projectsId}:setEnabled",
	//   "httpMethod": "POST",
	//   "id": "bigquerydatatransfer.projects.setEnabled",
	//   "parameterOrder": [
	//     "name"
	//   ],
	//   "parameters": {
	//     "name": {
	//       "description": "The name of the project resource in the form:\n`projects/{project_id}`",
	//       "location": "path",
	//       "pattern": "^projects/[^/]+$",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "v1/{+name}:setEnabled",
	//   "request": {
	//     "$ref": "SetEnabledRequest"
	//   },
	//   "response": {
	//     "$ref": "Empty"
	//   }
	// }

}

// method id "bigquerydatatransfer.projects.dataSources.checkValidCreds":

type ProjectsDataSourcesCheckValidCredsCall struct {
	s                      *Service
	name                   string
	checkvalidcredsrequest *CheckValidCredsRequest
	urlParams_             gensupport.URLParams
	ctx_                   context.Context
	header_                http.Header
}

// CheckValidCreds: Returns true if valid credentials exist for the
// given data source and
// requesting user.
func (r *ProjectsDataSourcesService) CheckValidCreds(name string, checkvalidcredsrequest *CheckValidCredsRequest) *ProjectsDataSourcesCheckValidCredsCall {
	c := &ProjectsDataSourcesCheckValidCredsCall{s: r.s, urlParams_: make(gensupport.URLParams)}
	c.name = name
	c.checkvalidcredsrequest = checkvalidcredsrequest
	return c
}

// Fields allows partial responses to be retrieved. See
// https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ProjectsDataSourcesCheckValidCredsCall) Fields(s ...googleapi.Field) *ProjectsDataSourcesCheckValidCredsCall {
	c.urlParams_.Set("fields", googleapi.CombineFields(s))
	return c
}

// Context sets the context to be used in this call's Do method. Any
// pending HTTP request will be aborted if the provided context is
// canceled.
func (c *ProjectsDataSourcesCheckValidCredsCall) Context(ctx context.Context) *ProjectsDataSourcesCheckValidCredsCall {
	c.ctx_ = ctx
	return c
}

// Header returns an http.Header that can be modified by the caller to
// add HTTP headers to the request.
func (c *ProjectsDataSourcesCheckValidCredsCall) Header() http.Header {
	if c.header_ == nil {
		c.header_ = make(http.Header)
	}
	return c.header_
}

func (c *ProjectsDataSourcesCheckValidCredsCall) doRequest(alt string) (*http.Response, error) {
	reqHeaders := make(http.Header)
	for k, v := range c.header_ {
		reqHeaders[k] = v
	}
	reqHeaders.Set("User-Agent", c.s.userAgent())
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.checkvalidcredsrequest)
	if err != nil {
		return nil, err
	}
	reqHeaders.Set("Content-Type", "application/json")
	c.urlParams_.Set("alt", alt)
	urls := googleapi.ResolveRelative(c.s.BasePath, "v1/{+name}:checkValidCreds")
	urls += "?" + c.urlParams_.Encode()
	req, _ := http.NewRequest("POST", urls, body)
	req.Header = reqHeaders
	googleapi.Expand(req.URL, map[string]string{
		"name": c.name,
	})
	return gensupport.SendRequest(c.ctx_, c.s.client, req)
}

// Do executes the "bigquerydatatransfer.projects.dataSources.checkValidCreds" call.
// Exactly one of *CheckValidCredsResponse or error will be non-nil. Any
// non-2xx status code is an error. Response headers are in either
// *CheckValidCredsResponse.ServerResponse.Header or (if a response was
// returned at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *ProjectsDataSourcesCheckValidCredsCall) Do(opts ...googleapi.CallOption) (*CheckValidCredsResponse, error) {
	gensupport.SetOptions(c.urlParams_, opts...)
	res, err := c.doRequest("json")
	if res != nil && res.StatusCode == http.StatusNotModified {
		if res.Body != nil {
			res.Body.Close()
		}
		return nil, &googleapi.Error{
			Code:   res.StatusCode,
			Header: res.Header,
		}
	}
	if err != nil {
		return nil, err
	}
	defer googleapi.CloseBody(res)
	if err := googleapi.CheckResponse(res); err != nil {
		return nil, err
	}
	ret := &CheckValidCredsResponse{
		ServerResponse: googleapi.ServerResponse{
			Header:         res.Header,
			HTTPStatusCode: res.StatusCode,
		},
	}
	target := &ret
	if err := json.NewDecoder(res.Body).Decode(target); err != nil {
		return nil, err
	}
	return ret, nil
	// {
	//   "description": "Returns true if valid credentials exist for the given data source and\nrequesting user.",
	//   "flatPath": "v1/projects/{projectsId}/dataSources/{dataSourcesId}:checkValidCreds",
	//   "httpMethod": "POST",
	//   "id": "bigquerydatatransfer.projects.dataSources.checkValidCreds",
	//   "parameterOrder": [
	//     "name"
	//   ],
	//   "parameters": {
	//     "name": {
	//       "description": "The data source in the form:\n`projects/{project_id}/dataSources/{data_source_id}`",
	//       "location": "path",
	//       "pattern": "^projects/[^/]+/dataSources/[^/]+$",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "v1/{+name}:checkValidCreds",
	//   "request": {
	//     "$ref": "CheckValidCredsRequest"
	//   },
	//   "response": {
	//     "$ref": "CheckValidCredsResponse"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/bigquery"
	//   ]
	// }

}

// method id "bigquerydatatransfer.projects.dataSources.get":

type ProjectsDataSourcesGetCall struct {
	s            *Service
	name         string
	urlParams_   gensupport.URLParams
	ifNoneMatch_ string
	ctx_         context.Context
	header_      http.Header
}

// Get: Retrieves a supported data source and returns its
// settings,
// which can be used for UI rendering.
func (r *ProjectsDataSourcesService) Get(name string) *ProjectsDataSourcesGetCall {
	c := &ProjectsDataSourcesGetCall{s: r.s, urlParams_: make(gensupport.URLParams)}
	c.name = name
	return c
}

// Fields allows partial responses to be retrieved. See
// https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ProjectsDataSourcesGetCall) Fields(s ...googleapi.Field) *ProjectsDataSourcesGetCall {
	c.urlParams_.Set("fields", googleapi.CombineFields(s))
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *ProjectsDataSourcesGetCall) IfNoneMatch(entityTag string) *ProjectsDataSourcesGetCall {
	c.ifNoneMatch_ = entityTag
	return c
}

// Context sets the context to be used in this call's Do method. Any
// pending HTTP request will be aborted if the provided context is
// canceled.
func (c *ProjectsDataSourcesGetCall) Context(ctx context.Context) *ProjectsDataSourcesGetCall {
	c.ctx_ = ctx
	return c
}

// Header returns an http.Header that can be modified by the caller to
// add HTTP headers to the request.
func (c *ProjectsDataSourcesGetCall) Header() http.Header {
	if c.header_ == nil {
		c.header_ = make(http.Header)
	}
	return c.header_
}

func (c *ProjectsDataSourcesGetCall) doRequest(alt string) (*http.Response, error) {
	reqHeaders := make(http.Header)
	for k, v := range c.header_ {
		reqHeaders[k] = v
	}
	reqHeaders.Set("User-Agent", c.s.userAgent())
	if c.ifNoneMatch_ != "" {
		reqHeaders.Set("If-None-Match", c.ifNoneMatch_)
	}
	var body io.Reader = nil
	c.urlParams_.Set("alt", alt)
	urls := googleapi.ResolveRelative(c.s.BasePath, "v1/{+name}")
	urls += "?" + c.urlParams_.Encode()
	req, _ := http.NewRequest("GET", urls, body)
	req.Header = reqHeaders
	googleapi.Expand(req.URL, map[string]string{
		"name": c.name,
	})
	return gensupport.SendRequest(c.ctx_, c.s.client, req)
}

// Do executes the "bigquerydatatransfer.projects.dataSources.get" call.
// Exactly one of *DataSource or error will be non-nil. Any non-2xx
// status code is an error. Response headers are in either
// *DataSource.ServerResponse.Header or (if a response was returned at
// all) in error.(*googleapi.Error).Header. Use googleapi.IsNotModified
// to check whether the returned error was because
// http.StatusNotModified was returned.
func (c *ProjectsDataSourcesGetCall) Do(opts ...googleapi.CallOption) (*DataSource, error) {
	gensupport.SetOptions(c.urlParams_, opts...)
	res, err := c.doRequest("json")
	if res != nil && res.StatusCode == http.StatusNotModified {
		if res.Body != nil {
			res.Body.Close()
		}
		return nil, &googleapi.Error{
			Code:   res.StatusCode,
			Header: res.Header,
		}
	}
	if err != nil {
		return nil, err
	}
	defer googleapi.CloseBody(res)
	if err := googleapi.CheckResponse(res); err != nil {
		return nil, err
	}
	ret := &DataSource{
		ServerResponse: googleapi.ServerResponse{
			Header:         res.Header,
			HTTPStatusCode: res.StatusCode,
		},
	}
	target := &ret
	if err := json.NewDecoder(res.Body).Decode(target); err != nil {
		return nil, err
	}
	return ret, nil
	// {
	//   "description": "Retrieves a supported data source and returns its settings,\nwhich can be used for UI rendering.",
	//   "flatPath": "v1/projects/{projectsId}/dataSources/{dataSourcesId}",
	//   "httpMethod": "GET",
	//   "id": "bigquerydatatransfer.projects.dataSources.get",
	//   "parameterOrder": [
	//     "name"
	//   ],
	//   "parameters": {
	//     "name": {
	//       "description": "The field will contain name of the resource requested, for example:\n`projects/{project_id}/dataSources/{data_source_id}`",
	//       "location": "path",
	//       "pattern": "^projects/[^/]+/dataSources/[^/]+$",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "v1/{+name}",
	//   "response": {
	//     "$ref": "DataSource"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/bigquery"
	//   ]
	// }

}

// method id "bigquerydatatransfer.projects.dataSources.list":

type ProjectsDataSourcesListCall struct {
	s            *Service
	parent       string
	urlParams_   gensupport.URLParams
	ifNoneMatch_ string
	ctx_         context.Context
	header_      http.Header
}

// List: Lists supported data sources and returns their settings,
// which can be used for UI rendering.
func (r *ProjectsDataSourcesService) List(parent string) *ProjectsDataSourcesListCall {
	c := &ProjectsDataSourcesListCall{s: r.s, urlParams_: make(gensupport.URLParams)}
	c.parent = parent
	return c
}

// PageSize sets the optional parameter "pageSize": Page size. The
// default page size is the maximum value of 1000 results.
func (c *ProjectsDataSourcesListCall) PageSize(pageSize int64) *ProjectsDataSourcesListCall {
	c.urlParams_.Set("pageSize", fmt.Sprint(pageSize))
	return c
}

// PageToken sets the optional parameter "pageToken": Pagination token,
// which can be used to request a specific page
// of `ListDataSourcesRequest` list results. For multiple-page
// results, `ListDataSourcesResponse` outputs
// a `next_page` token, which can be used as the
// `page_token` value to request the next page of list results.
func (c *ProjectsDataSourcesListCall) PageToken(pageToken string) *ProjectsDataSourcesListCall {
	c.urlParams_.Set("pageToken", pageToken)
	return c
}

// Fields allows partial responses to be retrieved. See
// https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ProjectsDataSourcesListCall) Fields(s ...googleapi.Field) *ProjectsDataSourcesListCall {
	c.urlParams_.Set("fields", googleapi.CombineFields(s))
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *ProjectsDataSourcesListCall) IfNoneMatch(entityTag string) *ProjectsDataSourcesListCall {
	c.ifNoneMatch_ = entityTag
	return c
}

// Context sets the context to be used in this call's Do method. Any
// pending HTTP request will be aborted if the provided context is
// canceled.
func (c *ProjectsDataSourcesListCall) Context(ctx context.Context) *ProjectsDataSourcesListCall {
	c.ctx_ = ctx
	return c
}

// Header returns an http.Header that can be modified by the caller to
// add HTTP headers to the request.
func (c *ProjectsDataSourcesListCall) Header() http.Header {
	if c.header_ == nil {
		c.header_ = make(http.Header)
	}
	return c.header_
}

func (c *ProjectsDataSourcesListCall) doRequest(alt string) (*http.Response, error) {
	reqHeaders := make(http.Header)
	for k, v := range c.header_ {
		reqHeaders[k] = v
	}
	reqHeaders.Set("User-Agent", c.s.userAgent())
	if c.ifNoneMatch_ != "" {
		reqHeaders.Set("If-None-Match", c.ifNoneMatch_)
	}
	var body io.Reader = nil
	c.urlParams_.Set("alt", alt)
	urls := googleapi.ResolveRelative(c.s.BasePath, "v1/{+parent}/dataSources")
	urls += "?" + c.urlParams_.Encode()
	req, _ := http.NewRequest("GET", urls, body)
	req.Header = reqHeaders
	googleapi.Expand(req.URL, map[string]string{
		"parent": c.parent,
	})
	return gensupport.SendRequest(c.ctx_, c.s.client, req)
}

// Do executes the "bigquerydatatransfer.projects.dataSources.list" call.
// Exactly one of *ListDataSourcesResponse or error will be non-nil. Any
// non-2xx status code is an error. Response headers are in either
// *ListDataSourcesResponse.ServerResponse.Header or (if a response was
// returned at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *ProjectsDataSourcesListCall) Do(opts ...googleapi.CallOption) (*ListDataSourcesResponse, error) {
	gensupport.SetOptions(c.urlParams_, opts...)
	res, err := c.doRequest("json")
	if res != nil && res.StatusCode == http.StatusNotModified {
		if res.Body != nil {
			res.Body.Close()
		}
		return nil, &googleapi.Error{
			Code:   res.StatusCode,
			Header: res.Header,
		}
	}
	if err != nil {
		return nil, err
	}
	defer googleapi.CloseBody(res)
	if err := googleapi.CheckResponse(res); err != nil {
		return nil, err
	}
	ret := &ListDataSourcesResponse{
		ServerResponse: googleapi.ServerResponse{
			Header:         res.Header,
			HTTPStatusCode: res.StatusCode,
		},
	}
	target := &ret
	if err := json.NewDecoder(res.Body).Decode(target); err != nil {
		return nil, err
	}
	return ret, nil
	// {
	//   "description": "Lists supported data sources and returns their settings,\nwhich can be used for UI rendering.",
	//   "flatPath": "v1/projects/{projectsId}/dataSources",
	//   "httpMethod": "GET",
	//   "id": "bigquerydatatransfer.projects.dataSources.list",
	//   "parameterOrder": [
	//     "parent"
	//   ],
	//   "parameters": {
	//     "pageSize": {
	//       "description": "Page size. The default page size is the maximum value of 1000 results.",
	//       "format": "int32",
	//       "location": "query",
	//       "type": "integer"
	//     },
	//     "pageToken": {
	//       "description": "Pagination token, which can be used to request a specific page\nof `ListDataSourcesRequest` list results. For multiple-page\nresults, `ListDataSourcesResponse` outputs\na `next_page` token, which can be used as the\n`page_token` value to request the next page of list results.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "parent": {
	//       "description": "The BigQuery project id for which data sources should be returned.\nMust be in the form: `projects/{project_id}`",
	//       "location": "path",
	//       "pattern": "^projects/[^/]+$",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "v1/{+parent}/dataSources",
	//   "response": {
	//     "$ref": "ListDataSourcesResponse"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/bigquery"
	//   ]
	// }

}

// Pages invokes f for each page of results.
// A non-nil error returned from f will halt the iteration.
// The provided context supersedes any context provided to the Context method.
func (c *ProjectsDataSourcesListCall) Pages(ctx context.Context, f func(*ListDataSourcesResponse) error) error {
	c.ctx_ = ctx
	defer c.PageToken(c.urlParams_.Get("pageToken")) // reset paging to original point
	for {
		x, err := c.Do()
		if err != nil {
			return err
		}
		if err := f(x); err != nil {
			return err
		}
		if x.NextPageToken == "" {
			return nil
		}
		c.PageToken(x.NextPageToken)
	}
}

// method id "bigquerydatatransfer.projects.transferConfigs.create":

type ProjectsTransferConfigsCreateCall struct {
	s              *Service
	parent         string
	transferconfig *TransferConfig
	urlParams_     gensupport.URLParams
	ctx_           context.Context
	header_        http.Header
}

// Create: Creates a new data transfer configuration.
func (r *ProjectsTransferConfigsService) Create(parent string, transferconfig *TransferConfig) *ProjectsTransferConfigsCreateCall {
	c := &ProjectsTransferConfigsCreateCall{s: r.s, urlParams_: make(gensupport.URLParams)}
	c.parent = parent
	c.transferconfig = transferconfig
	return c
}

// AuthorizationCode sets the optional parameter "authorizationCode":
// Optional OAuth2 authorization code to use with this transfer
// configuration.
// This is required if new credentials are needed, as indicated
// by
// `CheckValidCreds`.
// In order to obtain authorization_code, please make a
// request
// to
// https://www.gstatic.com/bigquerydatatransfer/oauthz/auth?client_id=
// <datatransferapiclientid>&scope=<data_source_scopes>&redirect_uri=<red
// irect_uri>
//
// * client_id should be OAuth client_id of BigQuery DTS API for the
// given
//   data source returned by ListDataSources method.
// * data_source_scopes are the scopes returned by ListDataSources
// method.
// * redirect_uri is an optional parameter. If not specified, then
//   authorization code is posted to the opener of authorization flow
// window.
//   Otherwise it will be sent to the redirect uri. A special value of
//   urn:ietf:wg:oauth:2.0:oob means that authorization code should be
//   returned in the title bar of the browser, with the page text
// prompting
//   the user to copy the code and paste it in the application.
func (c *ProjectsTransferConfigsCreateCall) AuthorizationCode(authorizationCode string) *ProjectsTransferConfigsCreateCall {
	c.urlParams_.Set("authorizationCode", authorizationCode)
	return c
}

// Fields allows partial responses to be retrieved. See
// https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ProjectsTransferConfigsCreateCall) Fields(s ...googleapi.Field) *ProjectsTransferConfigsCreateCall {
	c.urlParams_.Set("fields", googleapi.CombineFields(s))
	return c
}

// Context sets the context to be used in this call's Do method. Any
// pending HTTP request will be aborted if the provided context is
// canceled.
func (c *ProjectsTransferConfigsCreateCall) Context(ctx context.Context) *ProjectsTransferConfigsCreateCall {
	c.ctx_ = ctx
	return c
}

// Header returns an http.Header that can be modified by the caller to
// add HTTP headers to the request.
func (c *ProjectsTransferConfigsCreateCall) Header() http.Header {
	if c.header_ == nil {
		c.header_ = make(http.Header)
	}
	return c.header_
}

func (c *ProjectsTransferConfigsCreateCall) doRequest(alt string) (*http.Response, error) {
	reqHeaders := make(http.Header)
	for k, v := range c.header_ {
		reqHeaders[k] = v
	}
	reqHeaders.Set("User-Agent", c.s.userAgent())
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.transferconfig)
	if err != nil {
		return nil, err
	}
	reqHeaders.Set("Content-Type", "application/json")
	c.urlParams_.Set("alt", alt)
	urls := googleapi.ResolveRelative(c.s.BasePath, "v1/{+parent}/transferConfigs")
	urls += "?" + c.urlParams_.Encode()
	req, _ := http.NewRequest("POST", urls, body)
	req.Header = reqHeaders
	googleapi.Expand(req.URL, map[string]string{
		"parent": c.parent,
	})
	return gensupport.SendRequest(c.ctx_, c.s.client, req)
}

// Do executes the "bigquerydatatransfer.projects.transferConfigs.create" call.
// Exactly one of *TransferConfig or error will be non-nil. Any non-2xx
// status code is an error. Response headers are in either
// *TransferConfig.ServerResponse.Header or (if a response was returned
// at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *ProjectsTransferConfigsCreateCall) Do(opts ...googleapi.CallOption) (*TransferConfig, error) {
	gensupport.SetOptions(c.urlParams_, opts...)
	res, err := c.doRequest("json")
	if res != nil && res.StatusCode == http.StatusNotModified {
		if res.Body != nil {
			res.Body.Close()
		}
		return nil, &googleapi.Error{
			Code:   res.StatusCode,
			Header: res.Header,
		}
	}
	if err != nil {
		return nil, err
	}
	defer googleapi.CloseBody(res)
	if err := googleapi.CheckResponse(res); err != nil {
		return nil, err
	}
	ret := &TransferConfig{
		ServerResponse: googleapi.ServerResponse{
			Header:         res.Header,
			HTTPStatusCode: res.StatusCode,
		},
	}
	target := &ret
	if err := json.NewDecoder(res.Body).Decode(target); err != nil {
		return nil, err
	}
	return ret, nil
	// {
	//   "description": "Creates a new data transfer configuration.",
	//   "flatPath": "v1/projects/{projectsId}/transferConfigs",
	//   "httpMethod": "POST",
	//   "id": "bigquerydatatransfer.projects.transferConfigs.create",
	//   "parameterOrder": [
	//     "parent"
	//   ],
	//   "parameters": {
	//     "authorizationCode": {
	//       "description": "Optional OAuth2 authorization code to use with this transfer configuration.\nThis is required if new credentials are needed, as indicated by\n`CheckValidCreds`.\nIn order to obtain authorization_code, please make a\nrequest to\nhttps://www.gstatic.com/bigquerydatatransfer/oauthz/auth?client_id=\u003cdatatransferapiclientid\u003e\u0026scope=\u003cdata_source_scopes\u003e\u0026redirect_uri=\u003credirect_uri\u003e\n\n* client_id should be OAuth client_id of BigQuery DTS API for the given\n  data source returned by ListDataSources method.\n* data_source_scopes are the scopes returned by ListDataSources method.\n* redirect_uri is an optional parameter. If not specified, then\n  authorization code is posted to the opener of authorization flow window.\n  Otherwise it will be sent to the redirect uri. A special value of\n  urn:ietf:wg:oauth:2.0:oob means that authorization code should be\n  returned in the title bar of the browser, with the page text prompting\n  the user to copy the code and paste it in the application.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "parent": {
	//       "description": "The BigQuery project id where the transfer configuration should be created.",
	//       "location": "path",
	//       "pattern": "^projects/[^/]+$",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "v1/{+parent}/transferConfigs",
	//   "request": {
	//     "$ref": "TransferConfig"
	//   },
	//   "response": {
	//     "$ref": "TransferConfig"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/bigquery"
	//   ]
	// }

}

// method id "bigquerydatatransfer.projects.transferConfigs.delete":

type ProjectsTransferConfigsDeleteCall struct {
	s          *Service
	name       string
	urlParams_ gensupport.URLParams
	ctx_       context.Context
	header_    http.Header
}

// Delete: Deletes a data transfer configuration,
// including any associated transfer runs and logs.
func (r *ProjectsTransferConfigsService) Delete(name string) *ProjectsTransferConfigsDeleteCall {
	c := &ProjectsTransferConfigsDeleteCall{s: r.s, urlParams_: make(gensupport.URLParams)}
	c.name = name
	return c
}

// Fields allows partial responses to be retrieved. See
// https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ProjectsTransferConfigsDeleteCall) Fields(s ...googleapi.Field) *ProjectsTransferConfigsDeleteCall {
	c.urlParams_.Set("fields", googleapi.CombineFields(s))
	return c
}

// Context sets the context to be used in this call's Do method. Any
// pending HTTP request will be aborted if the provided context is
// canceled.
func (c *ProjectsTransferConfigsDeleteCall) Context(ctx context.Context) *ProjectsTransferConfigsDeleteCall {
	c.ctx_ = ctx
	return c
}

// Header returns an http.Header that can be modified by the caller to
// add HTTP headers to the request.
func (c *ProjectsTransferConfigsDeleteCall) Header() http.Header {
	if c.header_ == nil {
		c.header_ = make(http.Header)
	}
	return c.header_
}

func (c *ProjectsTransferConfigsDeleteCall) doRequest(alt string) (*http.Response, error) {
	reqHeaders := make(http.Header)
	for k, v := range c.header_ {
		reqHeaders[k] = v
	}
	reqHeaders.Set("User-Agent", c.s.userAgent())
	var body io.Reader = nil
	c.urlParams_.Set("alt", alt)
	urls := googleapi.ResolveRelative(c.s.BasePath, "v1/{+name}")
	urls += "?" + c.urlParams_.Encode()
	req, _ := http.NewRequest("DELETE", urls, body)
	req.Header = reqHeaders
	googleapi.Expand(req.URL, map[string]string{
		"name": c.name,
	})
	return gensupport.SendRequest(c.ctx_, c.s.client, req)
}

// Do executes the "bigquerydatatransfer.projects.transferConfigs.delete" call.
// Exactly one of *Empty or error will be non-nil. Any non-2xx status
// code is an error. Response headers are in either
// *Empty.ServerResponse.Header or (if a response was returned at all)
// in error.(*googleapi.Error).Header. Use googleapi.IsNotModified to
// check whether the returned error was because http.StatusNotModified
// was returned.
func (c *ProjectsTransferConfigsDeleteCall) Do(opts ...googleapi.CallOption) (*Empty, error) {
	gensupport.SetOptions(c.urlParams_, opts...)
	res, err := c.doRequest("json")
	if res != nil && res.StatusCode == http.StatusNotModified {
		if res.Body != nil {
			res.Body.Close()
		}
		return nil, &googleapi.Error{
			Code:   res.StatusCode,
			Header: res.Header,
		}
	}
	if err != nil {
		return nil, err
	}
	defer googleapi.CloseBody(res)
	if err := googleapi.CheckResponse(res); err != nil {
		return nil, err
	}
	ret := &Empty{
		ServerResponse: googleapi.ServerResponse{
			Header:         res.Header,
			HTTPStatusCode: res.StatusCode,
		},
	}
	target := &ret
	if err := json.NewDecoder(res.Body).Decode(target); err != nil {
		return nil, err
	}
	return ret, nil
	// {
	//   "description": "Deletes a data transfer configuration,\nincluding any associated transfer runs and logs.",
	//   "flatPath": "v1/projects/{projectsId}/transferConfigs/{transferConfigsId}",
	//   "httpMethod": "DELETE",
	//   "id": "bigquerydatatransfer.projects.transferConfigs.delete",
	//   "parameterOrder": [
	//     "name"
	//   ],
	//   "parameters": {
	//     "name": {
	//       "description": "The field will contain name of the resource requested, for example:\n`projects/{project_id}/transferConfigs/{config_id}`",
	//       "location": "path",
	//       "pattern": "^projects/[^/]+/transferConfigs/[^/]+$",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "v1/{+name}",
	//   "response": {
	//     "$ref": "Empty"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/bigquery"
	//   ]
	// }

}

// method id "bigquerydatatransfer.projects.transferConfigs.get":

type ProjectsTransferConfigsGetCall struct {
	s            *Service
	name         string
	urlParams_   gensupport.URLParams
	ifNoneMatch_ string
	ctx_         context.Context
	header_      http.Header
}

// Get: Returns information about a data transfer config.
func (r *ProjectsTransferConfigsService) Get(name string) *ProjectsTransferConfigsGetCall {
	c := &ProjectsTransferConfigsGetCall{s: r.s, urlParams_: make(gensupport.URLParams)}
	c.name = name
	return c
}

// Fields allows partial responses to be retrieved. See
// https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ProjectsTransferConfigsGetCall) Fields(s ...googleapi.Field) *ProjectsTransferConfigsGetCall {
	c.urlParams_.Set("fields", googleapi.CombineFields(s))
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *ProjectsTransferConfigsGetCall) IfNoneMatch(entityTag string) *ProjectsTransferConfigsGetCall {
	c.ifNoneMatch_ = entityTag
	return c
}

// Context sets the context to be used in this call's Do method. Any
// pending HTTP request will be aborted if the provided context is
// canceled.
func (c *ProjectsTransferConfigsGetCall) Context(ctx context.Context) *ProjectsTransferConfigsGetCall {
	c.ctx_ = ctx
	return c
}

// Header returns an http.Header that can be modified by the caller to
// add HTTP headers to the request.
func (c *ProjectsTransferConfigsGetCall) Header() http.Header {
	if c.header_ == nil {
		c.header_ = make(http.Header)
	}
	return c.header_
}

func (c *ProjectsTransferConfigsGetCall) doRequest(alt string) (*http.Response, error) {
	reqHeaders := make(http.Header)
	for k, v := range c.header_ {
		reqHeaders[k] = v
	}
	reqHeaders.Set("User-Agent", c.s.userAgent())
	if c.ifNoneMatch_ != "" {
		reqHeaders.Set("If-None-Match", c.ifNoneMatch_)
	}
	var body io.Reader = nil
	c.urlParams_.Set("alt", alt)
	urls := googleapi.ResolveRelative(c.s.BasePath, "v1/{+name}")
	urls += "?" + c.urlParams_.Encode()
	req, _ := http.NewRequest("GET", urls, body)
	req.Header = reqHeaders
	googleapi.Expand(req.URL, map[string]string{
		"name": c.name,
	})
	return gensupport.SendRequest(c.ctx_, c.s.client, req)
}

// Do executes the "bigquerydatatransfer.projects.transferConfigs.get" call.
// Exactly one of *TransferConfig or error will be non-nil. Any non-2xx
// status code is an error. Response headers are in either
// *TransferConfig.ServerResponse.Header or (if a response was returned
// at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *ProjectsTransferConfigsGetCall) Do(opts ...googleapi.CallOption) (*TransferConfig, error) {
	gensupport.SetOptions(c.urlParams_, opts...)
	res, err := c.doRequest("json")
	if res != nil && res.StatusCode == http.StatusNotModified {
		if res.Body != nil {
			res.Body.Close()
		}
		return nil, &googleapi.Error{
			Code:   res.StatusCode,
			Header: res.Header,
		}
	}
	if err != nil {
		return nil, err
	}
	defer googleapi.CloseBody(res)
	if err := googleapi.CheckResponse(res); err != nil {
		return nil, err
	}
	ret := &TransferConfig{
		ServerResponse: googleapi.ServerResponse{
			Header:         res.Header,
			HTTPStatusCode: res.StatusCode,
		},
	}
	target := &ret
	if err := json.NewDecoder(res.Body).Decode(target); err != nil {
		return nil, err
	}
	return ret, nil
	// {
	//   "description": "Returns information about a data transfer config.",
	//   "flatPath": "v1/projects/{projectsId}/transferConfigs/{transferConfigsId}",
	//   "httpMethod": "GET",
	//   "id": "bigquerydatatransfer.projects.transferConfigs.get",
	//   "parameterOrder": [
	//     "name"
	//   ],
	//   "parameters": {
	//     "name": {
	//       "description": "The field will contain name of the resource requested, for example:\n`projects/{project_id}/transferConfigs/{config_id}`",
	//       "location": "path",
	//       "pattern": "^projects/[^/]+/transferConfigs/[^/]+$",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "v1/{+name}",
	//   "response": {
	//     "$ref": "TransferConfig"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/bigquery"
	//   ]
	// }

}

// method id "bigquerydatatransfer.projects.transferConfigs.list":

type ProjectsTransferConfigsListCall struct {
	s            *Service
	parent       string
	urlParams_   gensupport.URLParams
	ifNoneMatch_ string
	ctx_         context.Context
	header_      http.Header
}

// List: Returns information about all data transfers in the project.
func (r *ProjectsTransferConfigsService) List(parent string) *ProjectsTransferConfigsListCall {
	c := &ProjectsTransferConfigsListCall{s: r.s, urlParams_: make(gensupport.URLParams)}
	c.parent = parent
	return c
}

// DataSourceIds sets the optional parameter "dataSourceIds": When
// specified, only configurations of requested data sources are
// returned.
func (c *ProjectsTransferConfigsListCall) DataSourceIds(dataSourceIds ...string) *ProjectsTransferConfigsListCall {
	c.urlParams_.SetMulti("dataSourceIds", append([]string{}, dataSourceIds...))
	return c
}

// PageSize sets the optional parameter "pageSize": Page size. The
// default page size is the maximum value of 1000 results.
func (c *ProjectsTransferConfigsListCall) PageSize(pageSize int64) *ProjectsTransferConfigsListCall {
	c.urlParams_.Set("pageSize", fmt.Sprint(pageSize))
	return c
}

// PageToken sets the optional parameter "pageToken": Pagination token,
// which can be used to request a specific page
// of `ListTransfersRequest` list results. For multiple-page
// results, `ListTransfersResponse` outputs
// a `next_page` token, which can be used as the
// `page_token` value to request the next page of list results.
func (c *ProjectsTransferConfigsListCall) PageToken(pageToken string) *ProjectsTransferConfigsListCall {
	c.urlParams_.Set("pageToken", pageToken)
	return c
}

// Fields allows partial responses to be retrieved. See
// https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ProjectsTransferConfigsListCall) Fields(s ...googleapi.Field) *ProjectsTransferConfigsListCall {
	c.urlParams_.Set("fields", googleapi.CombineFields(s))
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *ProjectsTransferConfigsListCall) IfNoneMatch(entityTag string) *ProjectsTransferConfigsListCall {
	c.ifNoneMatch_ = entityTag
	return c
}

// Context sets the context to be used in this call's Do method. Any
// pending HTTP request will be aborted if the provided context is
// canceled.
func (c *ProjectsTransferConfigsListCall) Context(ctx context.Context) *ProjectsTransferConfigsListCall {
	c.ctx_ = ctx
	return c
}

// Header returns an http.Header that can be modified by the caller to
// add HTTP headers to the request.
func (c *ProjectsTransferConfigsListCall) Header() http.Header {
	if c.header_ == nil {
		c.header_ = make(http.Header)
	}
	return c.header_
}

func (c *ProjectsTransferConfigsListCall) doRequest(alt string) (*http.Response, error) {
	reqHeaders := make(http.Header)
	for k, v := range c.header_ {
		reqHeaders[k] = v
	}
	reqHeaders.Set("User-Agent", c.s.userAgent())
	if c.ifNoneMatch_ != "" {
		reqHeaders.Set("If-None-Match", c.ifNoneMatch_)
	}
	var body io.Reader = nil
	c.urlParams_.Set("alt", alt)
	urls := googleapi.ResolveRelative(c.s.BasePath, "v1/{+parent}/transferConfigs")
	urls += "?" + c.urlParams_.Encode()
	req, _ := http.NewRequest("GET", urls, body)
	req.Header = reqHeaders
	googleapi.Expand(req.URL, map[string]string{
		"parent": c.parent,
	})
	return gensupport.SendRequest(c.ctx_, c.s.client, req)
}

// Do executes the "bigquerydatatransfer.projects.transferConfigs.list" call.
// Exactly one of *ListTransferConfigsResponse or error will be non-nil.
// Any non-2xx status code is an error. Response headers are in either
// *ListTransferConfigsResponse.ServerResponse.Header or (if a response
// was returned at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *ProjectsTransferConfigsListCall) Do(opts ...googleapi.CallOption) (*ListTransferConfigsResponse, error) {
	gensupport.SetOptions(c.urlParams_, opts...)
	res, err := c.doRequest("json")
	if res != nil && res.StatusCode == http.StatusNotModified {
		if res.Body != nil {
			res.Body.Close()
		}
		return nil, &googleapi.Error{
			Code:   res.StatusCode,
			Header: res.Header,
		}
	}
	if err != nil {
		return nil, err
	}
	defer googleapi.CloseBody(res)
	if err := googleapi.CheckResponse(res); err != nil {
		return nil, err
	}
	ret := &ListTransferConfigsResponse{
		ServerResponse: googleapi.ServerResponse{
			Header:         res.Header,
			HTTPStatusCode: res.StatusCode,
		},
	}
	target := &ret
	if err := json.NewDecoder(res.Body).Decode(target); err != nil {
		return nil, err
	}
	return ret, nil
	// {
	//   "description": "Returns information about all data transfers in the project.",
	//   "flatPath": "v1/projects/{projectsId}/transferConfigs",
	//   "httpMethod": "GET",
	//   "id": "bigquerydatatransfer.projects.transferConfigs.list",
	//   "parameterOrder": [
	//     "parent"
	//   ],
	//   "parameters": {
	//     "dataSourceIds": {
	//       "description": "When specified, only configurations of requested data sources are returned.",
	//       "location": "query",
	//       "repeated": true,
	//       "type": "string"
	//     },
	//     "pageSize": {
	//       "description": "Page size. The default page size is the maximum value of 1000 results.",
	//       "format": "int32",
	//       "location": "query",
	//       "type": "integer"
	//     },
	//     "pageToken": {
	//       "description": "Pagination token, which can be used to request a specific page\nof `ListTransfersRequest` list results. For multiple-page\nresults, `ListTransfersResponse` outputs\na `next_page` token, which can be used as the\n`page_token` value to request the next page of list results.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "parent": {
	//       "description": "The BigQuery project id for which data sources\nshould be returned: `projects/{project_id}`.",
	//       "location": "path",
	//       "pattern": "^projects/[^/]+$",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "v1/{+parent}/transferConfigs",
	//   "response": {
	//     "$ref": "ListTransferConfigsResponse"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/bigquery"
	//   ]
	// }

}

// Pages invokes f for each page of results.
// A non-nil error returned from f will halt the iteration.
// The provided context supersedes any context provided to the Context method.
func (c *ProjectsTransferConfigsListCall) Pages(ctx context.Context, f func(*ListTransferConfigsResponse) error) error {
	c.ctx_ = ctx
	defer c.PageToken(c.urlParams_.Get("pageToken")) // reset paging to original point
	for {
		x, err := c.Do()
		if err != nil {
			return err
		}
		if err := f(x); err != nil {
			return err
		}
		if x.NextPageToken == "" {
			return nil
		}
		c.PageToken(x.NextPageToken)
	}
}

// method id "bigquerydatatransfer.projects.transferConfigs.patch":

type ProjectsTransferConfigsPatchCall struct {
	s              *Service
	name           string
	transferconfig *TransferConfig
	urlParams_     gensupport.URLParams
	ctx_           context.Context
	header_        http.Header
}

// Patch: Updates a data transfer configuration.
// All fields must be set, even if they are not updated.
func (r *ProjectsTransferConfigsService) Patch(name string, transferconfig *TransferConfig) *ProjectsTransferConfigsPatchCall {
	c := &ProjectsTransferConfigsPatchCall{s: r.s, urlParams_: make(gensupport.URLParams)}
	c.name = name
	c.transferconfig = transferconfig
	return c
}

// AuthorizationCode sets the optional parameter "authorizationCode":
// Optional OAuth2 authorization code to use with this transfer
// configuration.
// If it is provided, the transfer configuration will be associated with
// the
// gaia id of the authorizing user.
// In order to obtain authorization_code, please make a
// request
// to
// https://www.gstatic.com/bigquerydatatransfer/oauthz/auth?client_id=
// <datatransferapiclientid>&scope=<data_source_scopes>&redirect_uri=<red
// irect_uri>
//
// * client_id should be OAuth client_id of BigQuery DTS API for the
// given
//   data source returned by ListDataSources method.
// * data_source_scopes are the scopes returned by ListDataSources
// method.
// * redirect_uri is an optional parameter. If not specified, then
//   authorization code is posted to the opener of authorization flow
// window.
//   Otherwise it will be sent to the redirect uri. A special value of
//   urn:ietf:wg:oauth:2.0:oob means that authorization code should be
//   returned in the title bar of the browser, with the page text
// prompting
//   the user to copy the code and paste it in the application.
func (c *ProjectsTransferConfigsPatchCall) AuthorizationCode(authorizationCode string) *ProjectsTransferConfigsPatchCall {
	c.urlParams_.Set("authorizationCode", authorizationCode)
	return c
}

// UpdateMask sets the optional parameter "updateMask": Required list of
// fields to be updated in this request.
func (c *ProjectsTransferConfigsPatchCall) UpdateMask(updateMask string) *ProjectsTransferConfigsPatchCall {
	c.urlParams_.Set("updateMask", updateMask)
	return c
}

// Fields allows partial responses to be retrieved. See
// https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ProjectsTransferConfigsPatchCall) Fields(s ...googleapi.Field) *ProjectsTransferConfigsPatchCall {
	c.urlParams_.Set("fields", googleapi.CombineFields(s))
	return c
}

// Context sets the context to be used in this call's Do method. Any
// pending HTTP request will be aborted if the provided context is
// canceled.
func (c *ProjectsTransferConfigsPatchCall) Context(ctx context.Context) *ProjectsTransferConfigsPatchCall {
	c.ctx_ = ctx
	return c
}

// Header returns an http.Header that can be modified by the caller to
// add HTTP headers to the request.
func (c *ProjectsTransferConfigsPatchCall) Header() http.Header {
	if c.header_ == nil {
		c.header_ = make(http.Header)
	}
	return c.header_
}

func (c *ProjectsTransferConfigsPatchCall) doRequest(alt string) (*http.Response, error) {
	reqHeaders := make(http.Header)
	for k, v := range c.header_ {
		reqHeaders[k] = v
	}
	reqHeaders.Set("User-Agent", c.s.userAgent())
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.transferconfig)
	if err != nil {
		return nil, err
	}
	reqHeaders.Set("Content-Type", "application/json")
	c.urlParams_.Set("alt", alt)
	urls := googleapi.ResolveRelative(c.s.BasePath, "v1/{+name}")
	urls += "?" + c.urlParams_.Encode()
	req, _ := http.NewRequest("PATCH", urls, body)
	req.Header = reqHeaders
	googleapi.Expand(req.URL, map[string]string{
		"name": c.name,
	})
	return gensupport.SendRequest(c.ctx_, c.s.client, req)
}

// Do executes the "bigquerydatatransfer.projects.transferConfigs.patch" call.
// Exactly one of *TransferConfig or error will be non-nil. Any non-2xx
// status code is an error. Response headers are in either
// *TransferConfig.ServerResponse.Header or (if a response was returned
// at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *ProjectsTransferConfigsPatchCall) Do(opts ...googleapi.CallOption) (*TransferConfig, error) {
	gensupport.SetOptions(c.urlParams_, opts...)
	res, err := c.doRequest("json")
	if res != nil && res.StatusCode == http.StatusNotModified {
		if res.Body != nil {
			res.Body.Close()
		}
		return nil, &googleapi.Error{
			Code:   res.StatusCode,
			Header: res.Header,
		}
	}
	if err != nil {
		return nil, err
	}
	defer googleapi.CloseBody(res)
	if err := googleapi.CheckResponse(res); err != nil {
		return nil, err
	}
	ret := &TransferConfig{
		ServerResponse: googleapi.ServerResponse{
			Header:         res.Header,
			HTTPStatusCode: res.StatusCode,
		},
	}
	target := &ret
	if err := json.NewDecoder(res.Body).Decode(target); err != nil {
		return nil, err
	}
	return ret, nil
	// {
	//   "description": "Updates a data transfer configuration.\nAll fields must be set, even if they are not updated.",
	//   "flatPath": "v1/projects/{projectsId}/transferConfigs/{transferConfigsId}",
	//   "httpMethod": "PATCH",
	//   "id": "bigquerydatatransfer.projects.transferConfigs.patch",
	//   "parameterOrder": [
	//     "name"
	//   ],
	//   "parameters": {
	//     "authorizationCode": {
	//       "description": "Optional OAuth2 authorization code to use with this transfer configuration.\nIf it is provided, the transfer configuration will be associated with the\ngaia id of the authorizing user.\nIn order to obtain authorization_code, please make a\nrequest to\nhttps://www.gstatic.com/bigquerydatatransfer/oauthz/auth?client_id=\u003cdatatransferapiclientid\u003e\u0026scope=\u003cdata_source_scopes\u003e\u0026redirect_uri=\u003credirect_uri\u003e\n\n* client_id should be OAuth client_id of BigQuery DTS API for the given\n  data source returned by ListDataSources method.\n* data_source_scopes are the scopes returned by ListDataSources method.\n* redirect_uri is an optional parameter. If not specified, then\n  authorization code is posted to the opener of authorization flow window.\n  Otherwise it will be sent to the redirect uri. A special value of\n  urn:ietf:wg:oauth:2.0:oob means that authorization code should be\n  returned in the title bar of the browser, with the page text prompting\n  the user to copy the code and paste it in the application.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "name": {
	//       "description": "The resource name of the transfer run.\nTransfer run names have the form\n`projects/{project_id}/transferConfigs/{config_id}`.\nWhere `config_id` is usually a uuid, even though it is not\nguaranteed or required. The name is ignored when creating a transfer run.",
	//       "location": "path",
	//       "pattern": "^projects/[^/]+/transferConfigs/[^/]+$",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "updateMask": {
	//       "description": "Required list of fields to be updated in this request.",
	//       "format": "google-fieldmask",
	//       "location": "query",
	//       "type": "string"
	//     }
	//   },
	//   "path": "v1/{+name}",
	//   "request": {
	//     "$ref": "TransferConfig"
	//   },
	//   "response": {
	//     "$ref": "TransferConfig"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/bigquery"
	//   ]
	// }

}

// method id "bigquerydatatransfer.projects.transferConfigs.scheduleRuns":

type ProjectsTransferConfigsScheduleRunsCall struct {
	s                           *Service
	parent                      string
	scheduletransferrunsrequest *ScheduleTransferRunsRequest
	urlParams_                  gensupport.URLParams
	ctx_                        context.Context
	header_                     http.Header
}

// ScheduleRuns: Creates transfer runs for a time range
// [range_start_time, range_end_time].
// For each date - or whatever granularity the data source supports - in
// the
// range, one transfer run is created.
// Note that runs are created per UTC time in the time range.
func (r *ProjectsTransferConfigsService) ScheduleRuns(parent string, scheduletransferrunsrequest *ScheduleTransferRunsRequest) *ProjectsTransferConfigsScheduleRunsCall {
	c := &ProjectsTransferConfigsScheduleRunsCall{s: r.s, urlParams_: make(gensupport.URLParams)}
	c.parent = parent
	c.scheduletransferrunsrequest = scheduletransferrunsrequest
	return c
}

// Fields allows partial responses to be retrieved. See
// https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ProjectsTransferConfigsScheduleRunsCall) Fields(s ...googleapi.Field) *ProjectsTransferConfigsScheduleRunsCall {
	c.urlParams_.Set("fields", googleapi.CombineFields(s))
	return c
}

// Context sets the context to be used in this call's Do method. Any
// pending HTTP request will be aborted if the provided context is
// canceled.
func (c *ProjectsTransferConfigsScheduleRunsCall) Context(ctx context.Context) *ProjectsTransferConfigsScheduleRunsCall {
	c.ctx_ = ctx
	return c
}

// Header returns an http.Header that can be modified by the caller to
// add HTTP headers to the request.
func (c *ProjectsTransferConfigsScheduleRunsCall) Header() http.Header {
	if c.header_ == nil {
		c.header_ = make(http.Header)
	}
	return c.header_
}

func (c *ProjectsTransferConfigsScheduleRunsCall) doRequest(alt string) (*http.Response, error) {
	reqHeaders := make(http.Header)
	for k, v := range c.header_ {
		reqHeaders[k] = v
	}
	reqHeaders.Set("User-Agent", c.s.userAgent())
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.scheduletransferrunsrequest)
	if err != nil {
		return nil, err
	}
	reqHeaders.Set("Content-Type", "application/json")
	c.urlParams_.Set("alt", alt)
	urls := googleapi.ResolveRelative(c.s.BasePath, "v1/{+parent}:scheduleRuns")
	urls += "?" + c.urlParams_.Encode()
	req, _ := http.NewRequest("POST", urls, body)
	req.Header = reqHeaders
	googleapi.Expand(req.URL, map[string]string{
		"parent": c.parent,
	})
	return gensupport.SendRequest(c.ctx_, c.s.client, req)
}

// Do executes the "bigquerydatatransfer.projects.transferConfigs.scheduleRuns" call.
// Exactly one of *ScheduleTransferRunsResponse or error will be
// non-nil. Any non-2xx status code is an error. Response headers are in
// either *ScheduleTransferRunsResponse.ServerResponse.Header or (if a
// response was returned at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *ProjectsTransferConfigsScheduleRunsCall) Do(opts ...googleapi.CallOption) (*ScheduleTransferRunsResponse, error) {
	gensupport.SetOptions(c.urlParams_, opts...)
	res, err := c.doRequest("json")
	if res != nil && res.StatusCode == http.StatusNotModified {
		if res.Body != nil {
			res.Body.Close()
		}
		return nil, &googleapi.Error{
			Code:   res.StatusCode,
			Header: res.Header,
		}
	}
	if err != nil {
		return nil, err
	}
	defer googleapi.CloseBody(res)
	if err := googleapi.CheckResponse(res); err != nil {
		return nil, err
	}
	ret := &ScheduleTransferRunsResponse{
		ServerResponse: googleapi.ServerResponse{
			Header:         res.Header,
			HTTPStatusCode: res.StatusCode,
		},
	}
	target := &ret
	if err := json.NewDecoder(res.Body).Decode(target); err != nil {
		return nil, err
	}
	return ret, nil
	// {
	//   "description": "Creates transfer runs for a time range [range_start_time, range_end_time].\nFor each date - or whatever granularity the data source supports - in the\nrange, one transfer run is created.\nNote that runs are created per UTC time in the time range.",
	//   "flatPath": "v1/projects/{projectsId}/transferConfigs/{transferConfigsId}:scheduleRuns",
	//   "httpMethod": "POST",
	//   "id": "bigquerydatatransfer.projects.transferConfigs.scheduleRuns",
	//   "parameterOrder": [
	//     "parent"
	//   ],
	//   "parameters": {
	//     "parent": {
	//       "description": "Transfer configuration name in the form:\n`projects/{project_id}/transferConfigs/{config_id}`.",
	//       "location": "path",
	//       "pattern": "^projects/[^/]+/transferConfigs/[^/]+$",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "v1/{+parent}:scheduleRuns",
	//   "request": {
	//     "$ref": "ScheduleTransferRunsRequest"
	//   },
	//   "response": {
	//     "$ref": "ScheduleTransferRunsResponse"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/bigquery"
	//   ]
	// }

}

// method id "bigquerydatatransfer.projects.transferConfigs.runs.delete":

type ProjectsTransferConfigsRunsDeleteCall struct {
	s          *Service
	name       string
	urlParams_ gensupport.URLParams
	ctx_       context.Context
	header_    http.Header
}

// Delete: Deletes the specified transfer run.
func (r *ProjectsTransferConfigsRunsService) Delete(name string) *ProjectsTransferConfigsRunsDeleteCall {
	c := &ProjectsTransferConfigsRunsDeleteCall{s: r.s, urlParams_: make(gensupport.URLParams)}
	c.name = name
	return c
}

// Fields allows partial responses to be retrieved. See
// https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ProjectsTransferConfigsRunsDeleteCall) Fields(s ...googleapi.Field) *ProjectsTransferConfigsRunsDeleteCall {
	c.urlParams_.Set("fields", googleapi.CombineFields(s))
	return c
}

// Context sets the context to be used in this call's Do method. Any
// pending HTTP request will be aborted if the provided context is
// canceled.
func (c *ProjectsTransferConfigsRunsDeleteCall) Context(ctx context.Context) *ProjectsTransferConfigsRunsDeleteCall {
	c.ctx_ = ctx
	return c
}

// Header returns an http.Header that can be modified by the caller to
// add HTTP headers to the request.
func (c *ProjectsTransferConfigsRunsDeleteCall) Header() http.Header {
	if c.header_ == nil {
		c.header_ = make(http.Header)
	}
	return c.header_
}

func (c *ProjectsTransferConfigsRunsDeleteCall) doRequest(alt string) (*http.Response, error) {
	reqHeaders := make(http.Header)
	for k, v := range c.header_ {
		reqHeaders[k] = v
	}
	reqHeaders.Set("User-Agent", c.s.userAgent())
	var body io.Reader = nil
	c.urlParams_.Set("alt", alt)
	urls := googleapi.ResolveRelative(c.s.BasePath, "v1/{+name}")
	urls += "?" + c.urlParams_.Encode()
	req, _ := http.NewRequest("DELETE", urls, body)
	req.Header = reqHeaders
	googleapi.Expand(req.URL, map[string]string{
		"name": c.name,
	})
	return gensupport.SendRequest(c.ctx_, c.s.client, req)
}

// Do executes the "bigquerydatatransfer.projects.transferConfigs.runs.delete" call.
// Exactly one of *Empty or error will be non-nil. Any non-2xx status
// code is an error. Response headers are in either
// *Empty.ServerResponse.Header or (if a response was returned at all)
// in error.(*googleapi.Error).Header. Use googleapi.IsNotModified to
// check whether the returned error was because http.StatusNotModified
// was returned.
func (c *ProjectsTransferConfigsRunsDeleteCall) Do(opts ...googleapi.CallOption) (*Empty, error) {
	gensupport.SetOptions(c.urlParams_, opts...)
	res, err := c.doRequest("json")
	if res != nil && res.StatusCode == http.StatusNotModified {
		if res.Body != nil {
			res.Body.Close()
		}
		return nil, &googleapi.Error{
			Code:   res.StatusCode,
			Header: res.Header,
		}
	}
	if err != nil {
		return nil, err
	}
	defer googleapi.CloseBody(res)
	if err := googleapi.CheckResponse(res); err != nil {
		return nil, err
	}
	ret := &Empty{
		ServerResponse: googleapi.ServerResponse{
			Header:         res.Header,
			HTTPStatusCode: res.StatusCode,
		},
	}
	target := &ret
	if err := json.NewDecoder(res.Body).Decode(target); err != nil {
		return nil, err
	}
	return ret, nil
	// {
	//   "description": "Deletes the specified transfer run.",
	//   "flatPath": "v1/projects/{projectsId}/transferConfigs/{transferConfigsId}/runs/{runsId}",
	//   "httpMethod": "DELETE",
	//   "id": "bigquerydatatransfer.projects.transferConfigs.runs.delete",
	//   "parameterOrder": [
	//     "name"
	//   ],
	//   "parameters": {
	//     "name": {
	//       "description": "The field will contain name of the resource requested, for example:\n`projects/{project_id}/transferConfigs/{config_id}/runs/{run_id}`",
	//       "location": "path",
	//       "pattern": "^projects/[^/]+/transferConfigs/[^/]+/runs/[^/]+$",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "v1/{+name}",
	//   "response": {
	//     "$ref": "Empty"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/bigquery"
	//   ]
	// }

}

// method id "bigquerydatatransfer.projects.transferConfigs.runs.get":

type ProjectsTransferConfigsRunsGetCall struct {
	s            *Service
	name         string
	urlParams_   gensupport.URLParams
	ifNoneMatch_ string
	ctx_         context.Context
	header_      http.Header
}

// Get: Returns information about the particular transfer run.
func (r *ProjectsTransferConfigsRunsService) Get(name string) *ProjectsTransferConfigsRunsGetCall {
	c := &ProjectsTransferConfigsRunsGetCall{s: r.s, urlParams_: make(gensupport.URLParams)}
	c.name = name
	return c
}

// Fields allows partial responses to be retrieved. See
// https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ProjectsTransferConfigsRunsGetCall) Fields(s ...googleapi.Field) *ProjectsTransferConfigsRunsGetCall {
	c.urlParams_.Set("fields", googleapi.CombineFields(s))
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *ProjectsTransferConfigsRunsGetCall) IfNoneMatch(entityTag string) *ProjectsTransferConfigsRunsGetCall {
	c.ifNoneMatch_ = entityTag
	return c
}

// Context sets the context to be used in this call's Do method. Any
// pending HTTP request will be aborted if the provided context is
// canceled.
func (c *ProjectsTransferConfigsRunsGetCall) Context(ctx context.Context) *ProjectsTransferConfigsRunsGetCall {
	c.ctx_ = ctx
	return c
}

// Header returns an http.Header that can be modified by the caller to
// add HTTP headers to the request.
func (c *ProjectsTransferConfigsRunsGetCall) Header() http.Header {
	if c.header_ == nil {
		c.header_ = make(http.Header)
	}
	return c.header_
}

func (c *ProjectsTransferConfigsRunsGetCall) doRequest(alt string) (*http.Response, error) {
	reqHeaders := make(http.Header)
	for k, v := range c.header_ {
		reqHeaders[k] = v
	}
	reqHeaders.Set("User-Agent", c.s.userAgent())
	if c.ifNoneMatch_ != "" {
		reqHeaders.Set("If-None-Match", c.ifNoneMatch_)
	}
	var body io.Reader = nil
	c.urlParams_.Set("alt", alt)
	urls := googleapi.ResolveRelative(c.s.BasePath, "v1/{+name}")
	urls += "?" + c.urlParams_.Encode()
	req, _ := http.NewRequest("GET", urls, body)
	req.Header = reqHeaders
	googleapi.Expand(req.URL, map[string]string{
		"name": c.name,
	})
	return gensupport.SendRequest(c.ctx_, c.s.client, req)
}

// Do executes the "bigquerydatatransfer.projects.transferConfigs.runs.get" call.
// Exactly one of *TransferRun or error will be non-nil. Any non-2xx
// status code is an error. Response headers are in either
// *TransferRun.ServerResponse.Header or (if a response was returned at
// all) in error.(*googleapi.Error).Header. Use googleapi.IsNotModified
// to check whether the returned error was because
// http.StatusNotModified was returned.
func (c *ProjectsTransferConfigsRunsGetCall) Do(opts ...googleapi.CallOption) (*TransferRun, error) {
	gensupport.SetOptions(c.urlParams_, opts...)
	res, err := c.doRequest("json")
	if res != nil && res.StatusCode == http.StatusNotModified {
		if res.Body != nil {
			res.Body.Close()
		}
		return nil, &googleapi.Error{
			Code:   res.StatusCode,
			Header: res.Header,
		}
	}
	if err != nil {
		return nil, err
	}
	defer googleapi.CloseBody(res)
	if err := googleapi.CheckResponse(res); err != nil {
		return nil, err
	}
	ret := &TransferRun{
		ServerResponse: googleapi.ServerResponse{
			Header:         res.Header,
			HTTPStatusCode: res.StatusCode,
		},
	}
	target := &ret
	if err := json.NewDecoder(res.Body).Decode(target); err != nil {
		return nil, err
	}
	return ret, nil
	// {
	//   "description": "Returns information about the particular transfer run.",
	//   "flatPath": "v1/projects/{projectsId}/transferConfigs/{transferConfigsId}/runs/{runsId}",
	//   "httpMethod": "GET",
	//   "id": "bigquerydatatransfer.projects.transferConfigs.runs.get",
	//   "parameterOrder": [
	//     "name"
	//   ],
	//   "parameters": {
	//     "name": {
	//       "description": "The field will contain name of the resource requested, for example:\n`projects/{project_id}/transferConfigs/{config_id}/runs/{run_id}`",
	//       "location": "path",
	//       "pattern": "^projects/[^/]+/transferConfigs/[^/]+/runs/[^/]+$",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "v1/{+name}",
	//   "response": {
	//     "$ref": "TransferRun"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/bigquery"
	//   ]
	// }

}

// method id "bigquerydatatransfer.projects.transferConfigs.runs.list":

type ProjectsTransferConfigsRunsListCall struct {
	s            *Service
	parent       string
	urlParams_   gensupport.URLParams
	ifNoneMatch_ string
	ctx_         context.Context
	header_      http.Header
}

// List: Returns information about running and completed jobs.
func (r *ProjectsTransferConfigsRunsService) List(parent string) *ProjectsTransferConfigsRunsListCall {
	c := &ProjectsTransferConfigsRunsListCall{s: r.s, urlParams_: make(gensupport.URLParams)}
	c.parent = parent
	return c
}

// PageSize sets the optional parameter "pageSize": Page size. The
// default page size is the maximum value of 1000 results.
func (c *ProjectsTransferConfigsRunsListCall) PageSize(pageSize int64) *ProjectsTransferConfigsRunsListCall {
	c.urlParams_.Set("pageSize", fmt.Sprint(pageSize))
	return c
}

// PageToken sets the optional parameter "pageToken": Pagination token,
// which can be used to request a specific page
// of `ListTransferRunsRequest` list results. For multiple-page
// results, `ListTransferRunsResponse` outputs
// a `next_page` token, which can be used as the
// `page_token` value to request the next page of list results.
func (c *ProjectsTransferConfigsRunsListCall) PageToken(pageToken string) *ProjectsTransferConfigsRunsListCall {
	c.urlParams_.Set("pageToken", pageToken)
	return c
}

// RunAttempt sets the optional parameter "runAttempt": Indicates how
// run attempts are to be pulled.
//
// Possible values:
//   "RUN_ATTEMPT_UNSPECIFIED"
//   "LATEST"
func (c *ProjectsTransferConfigsRunsListCall) RunAttempt(runAttempt string) *ProjectsTransferConfigsRunsListCall {
	c.urlParams_.Set("runAttempt", runAttempt)
	return c
}

// Statuses sets the optional parameter "statuses": When specified, only
// transfer runs with requested statuses are returned.
//
// Possible values:
//   "TRANSFER_STATUS_UNSPECIFIED"
//   "INACTIVE"
//   "PENDING"
//   "RUNNING"
//   "SUCCEEDED"
//   "FAILED"
//   "CANCELLED"
func (c *ProjectsTransferConfigsRunsListCall) Statuses(statuses ...string) *ProjectsTransferConfigsRunsListCall {
	c.urlParams_.SetMulti("statuses", append([]string{}, statuses...))
	return c
}

// Fields allows partial responses to be retrieved. See
// https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ProjectsTransferConfigsRunsListCall) Fields(s ...googleapi.Field) *ProjectsTransferConfigsRunsListCall {
	c.urlParams_.Set("fields", googleapi.CombineFields(s))
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *ProjectsTransferConfigsRunsListCall) IfNoneMatch(entityTag string) *ProjectsTransferConfigsRunsListCall {
	c.ifNoneMatch_ = entityTag
	return c
}

// Context sets the context to be used in this call's Do method. Any
// pending HTTP request will be aborted if the provided context is
// canceled.
func (c *ProjectsTransferConfigsRunsListCall) Context(ctx context.Context) *ProjectsTransferConfigsRunsListCall {
	c.ctx_ = ctx
	return c
}

// Header returns an http.Header that can be modified by the caller to
// add HTTP headers to the request.
func (c *ProjectsTransferConfigsRunsListCall) Header() http.Header {
	if c.header_ == nil {
		c.header_ = make(http.Header)
	}
	return c.header_
}

func (c *ProjectsTransferConfigsRunsListCall) doRequest(alt string) (*http.Response, error) {
	reqHeaders := make(http.Header)
	for k, v := range c.header_ {
		reqHeaders[k] = v
	}
	reqHeaders.Set("User-Agent", c.s.userAgent())
	if c.ifNoneMatch_ != "" {
		reqHeaders.Set("If-None-Match", c.ifNoneMatch_)
	}
	var body io.Reader = nil
	c.urlParams_.Set("alt", alt)
	urls := googleapi.ResolveRelative(c.s.BasePath, "v1/{+parent}/runs")
	urls += "?" + c.urlParams_.Encode()
	req, _ := http.NewRequest("GET", urls, body)
	req.Header = reqHeaders
	googleapi.Expand(req.URL, map[string]string{
		"parent": c.parent,
	})
	return gensupport.SendRequest(c.ctx_, c.s.client, req)
}

// Do executes the "bigquerydatatransfer.projects.transferConfigs.runs.list" call.
// Exactly one of *ListTransferRunsResponse or error will be non-nil.
// Any non-2xx status code is an error. Response headers are in either
// *ListTransferRunsResponse.ServerResponse.Header or (if a response was
// returned at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *ProjectsTransferConfigsRunsListCall) Do(opts ...googleapi.CallOption) (*ListTransferRunsResponse, error) {
	gensupport.SetOptions(c.urlParams_, opts...)
	res, err := c.doRequest("json")
	if res != nil && res.StatusCode == http.StatusNotModified {
		if res.Body != nil {
			res.Body.Close()
		}
		return nil, &googleapi.Error{
			Code:   res.StatusCode,
			Header: res.Header,
		}
	}
	if err != nil {
		return nil, err
	}
	defer googleapi.CloseBody(res)
	if err := googleapi.CheckResponse(res); err != nil {
		return nil, err
	}
	ret := &ListTransferRunsResponse{
		ServerResponse: googleapi.ServerResponse{
			Header:         res.Header,
			HTTPStatusCode: res.StatusCode,
		},
	}
	target := &ret
	if err := json.NewDecoder(res.Body).Decode(target); err != nil {
		return nil, err
	}
	return ret, nil
	// {
	//   "description": "Returns information about running and completed jobs.",
	//   "flatPath": "v1/projects/{projectsId}/transferConfigs/{transferConfigsId}/runs",
	//   "httpMethod": "GET",
	//   "id": "bigquerydatatransfer.projects.transferConfigs.runs.list",
	//   "parameterOrder": [
	//     "parent"
	//   ],
	//   "parameters": {
	//     "pageSize": {
	//       "description": "Page size. The default page size is the maximum value of 1000 results.",
	//       "format": "int32",
	//       "location": "query",
	//       "type": "integer"
	//     },
	//     "pageToken": {
	//       "description": "Pagination token, which can be used to request a specific page\nof `ListTransferRunsRequest` list results. For multiple-page\nresults, `ListTransferRunsResponse` outputs\na `next_page` token, which can be used as the\n`page_token` value to request the next page of list results.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "parent": {
	//       "description": "Name of transfer configuration for which transfer runs should be retrieved.\nFormat of transfer configuration resource name is:\n`projects/{project_id}/transferConfigs/{config_id}`.",
	//       "location": "path",
	//       "pattern": "^projects/[^/]+/transferConfigs/[^/]+$",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "runAttempt": {
	//       "description": "Indicates how run attempts are to be pulled.",
	//       "enum": [
	//         "RUN_ATTEMPT_UNSPECIFIED",
	//         "LATEST"
	//       ],
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "statuses": {
	//       "description": "When specified, only transfer runs with requested statuses are returned.",
	//       "enum": [
	//         "TRANSFER_STATUS_UNSPECIFIED",
	//         "INACTIVE",
	//         "PENDING",
	//         "RUNNING",
	//         "SUCCEEDED",
	//         "FAILED",
	//         "CANCELLED"
	//       ],
	//       "location": "query",
	//       "repeated": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "v1/{+parent}/runs",
	//   "response": {
	//     "$ref": "ListTransferRunsResponse"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/bigquery"
	//   ]
	// }

}

// Pages invokes f for each page of results.
// A non-nil error returned from f will halt the iteration.
// The provided context supersedes any context provided to the Context method.
func (c *ProjectsTransferConfigsRunsListCall) Pages(ctx context.Context, f func(*ListTransferRunsResponse) error) error {
	c.ctx_ = ctx
	defer c.PageToken(c.urlParams_.Get("pageToken")) // reset paging to original point
	for {
		x, err := c.Do()
		if err != nil {
			return err
		}
		if err := f(x); err != nil {
			return err
		}
		if x.NextPageToken == "" {
			return nil
		}
		c.PageToken(x.NextPageToken)
	}
}

// method id "bigquerydatatransfer.projects.transferConfigs.runs.transferLogs.list":

type ProjectsTransferConfigsRunsTransferLogsListCall struct {
	s            *Service
	parent       string
	urlParams_   gensupport.URLParams
	ifNoneMatch_ string
	ctx_         context.Context
	header_      http.Header
}

// List: Returns user facing log messages for the data transfer run.
func (r *ProjectsTransferConfigsRunsTransferLogsService) List(parent string) *ProjectsTransferConfigsRunsTransferLogsListCall {
	c := &ProjectsTransferConfigsRunsTransferLogsListCall{s: r.s, urlParams_: make(gensupport.URLParams)}
	c.parent = parent
	return c
}

// MessageTypes sets the optional parameter "messageTypes": Message
// types to return. If not populated - INFO, WARNING and ERROR
// messages are returned.
//
// Possible values:
//   "MESSAGE_SEVERITY_UNSPECIFIED"
//   "INFO"
//   "WARNING"
//   "ERROR"
func (c *ProjectsTransferConfigsRunsTransferLogsListCall) MessageTypes(messageTypes ...string) *ProjectsTransferConfigsRunsTransferLogsListCall {
	c.urlParams_.SetMulti("messageTypes", append([]string{}, messageTypes...))
	return c
}

// PageSize sets the optional parameter "pageSize": Page size. The
// default page size is the maximum value of 1000 results.
func (c *ProjectsTransferConfigsRunsTransferLogsListCall) PageSize(pageSize int64) *ProjectsTransferConfigsRunsTransferLogsListCall {
	c.urlParams_.Set("pageSize", fmt.Sprint(pageSize))
	return c
}

// PageToken sets the optional parameter "pageToken": Pagination token,
// which can be used to request a specific page
// of `ListTransferLogsRequest` list results. For multiple-page
// results, `ListTransferLogsResponse` outputs
// a `next_page` token, which can be used as the
// `page_token` value to request the next page of list results.
func (c *ProjectsTransferConfigsRunsTransferLogsListCall) PageToken(pageToken string) *ProjectsTransferConfigsRunsTransferLogsListCall {
	c.urlParams_.Set("pageToken", pageToken)
	return c
}

// Fields allows partial responses to be retrieved. See
// https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ProjectsTransferConfigsRunsTransferLogsListCall) Fields(s ...googleapi.Field) *ProjectsTransferConfigsRunsTransferLogsListCall {
	c.urlParams_.Set("fields", googleapi.CombineFields(s))
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *ProjectsTransferConfigsRunsTransferLogsListCall) IfNoneMatch(entityTag string) *ProjectsTransferConfigsRunsTransferLogsListCall {
	c.ifNoneMatch_ = entityTag
	return c
}

// Context sets the context to be used in this call's Do method. Any
// pending HTTP request will be aborted if the provided context is
// canceled.
func (c *ProjectsTransferConfigsRunsTransferLogsListCall) Context(ctx context.Context) *ProjectsTransferConfigsRunsTransferLogsListCall {
	c.ctx_ = ctx
	return c
}

// Header returns an http.Header that can be modified by the caller to
// add HTTP headers to the request.
func (c *ProjectsTransferConfigsRunsTransferLogsListCall) Header() http.Header {
	if c.header_ == nil {
		c.header_ = make(http.Header)
	}
	return c.header_
}

func (c *ProjectsTransferConfigsRunsTransferLogsListCall) doRequest(alt string) (*http.Response, error) {
	reqHeaders := make(http.Header)
	for k, v := range c.header_ {
		reqHeaders[k] = v
	}
	reqHeaders.Set("User-Agent", c.s.userAgent())
	if c.ifNoneMatch_ != "" {
		reqHeaders.Set("If-None-Match", c.ifNoneMatch_)
	}
	var body io.Reader = nil
	c.urlParams_.Set("alt", alt)
	urls := googleapi.ResolveRelative(c.s.BasePath, "v1/{+parent}/transferLogs")
	urls += "?" + c.urlParams_.Encode()
	req, _ := http.NewRequest("GET", urls, body)
	req.Header = reqHeaders
	googleapi.Expand(req.URL, map[string]string{
		"parent": c.parent,
	})
	return gensupport.SendRequest(c.ctx_, c.s.client, req)
}

// Do executes the "bigquerydatatransfer.projects.transferConfigs.runs.transferLogs.list" call.
// Exactly one of *ListTransferLogsResponse or error will be non-nil.
// Any non-2xx status code is an error. Response headers are in either
// *ListTransferLogsResponse.ServerResponse.Header or (if a response was
// returned at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *ProjectsTransferConfigsRunsTransferLogsListCall) Do(opts ...googleapi.CallOption) (*ListTransferLogsResponse, error) {
	gensupport.SetOptions(c.urlParams_, opts...)
	res, err := c.doRequest("json")
	if res != nil && res.StatusCode == http.StatusNotModified {
		if res.Body != nil {
			res.Body.Close()
		}
		return nil, &googleapi.Error{
			Code:   res.StatusCode,
			Header: res.Header,
		}
	}
	if err != nil {
		return nil, err
	}
	defer googleapi.CloseBody(res)
	if err := googleapi.CheckResponse(res); err != nil {
		return nil, err
	}
	ret := &ListTransferLogsResponse{
		ServerResponse: googleapi.ServerResponse{
			Header:         res.Header,
			HTTPStatusCode: res.StatusCode,
		},
	}
	target := &ret
	if err := json.NewDecoder(res.Body).Decode(target); err != nil {
		return nil, err
	}
	return ret, nil
	// {
	//   "description": "Returns user facing log messages for the data transfer run.",
	//   "flatPath": "v1/projects/{projectsId}/transferConfigs/{transferConfigsId}/runs/{runsId}/transferLogs",
	//   "httpMethod": "GET",
	//   "id": "bigquerydatatransfer.projects.transferConfigs.runs.transferLogs.list",
	//   "parameterOrder": [
	//     "parent"
	//   ],
	//   "parameters": {
	//     "messageTypes": {
	//       "description": "Message types to return. If not populated - INFO, WARNING and ERROR\nmessages are returned.",
	//       "enum": [
	//         "MESSAGE_SEVERITY_UNSPECIFIED",
	//         "INFO",
	//         "WARNING",
	//         "ERROR"
	//       ],
	//       "location": "query",
	//       "repeated": true,
	//       "type": "string"
	//     },
	//     "pageSize": {
	//       "description": "Page size. The default page size is the maximum value of 1000 results.",
	//       "format": "int32",
	//       "location": "query",
	//       "type": "integer"
	//     },
	//     "pageToken": {
	//       "description": "Pagination token, which can be used to request a specific page\nof `ListTransferLogsRequest` list results. For multiple-page\nresults, `ListTransferLogsResponse` outputs\na `next_page` token, which can be used as the\n`page_token` value to request the next page of list results.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "parent": {
	//       "description": "Transfer run name in the form:\n`projects/{project_id}/transferConfigs/{config_Id}/runs/{run_id}`.",
	//       "location": "path",
	//       "pattern": "^projects/[^/]+/transferConfigs/[^/]+/runs/[^/]+$",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "v1/{+parent}/transferLogs",
	//   "response": {
	//     "$ref": "ListTransferLogsResponse"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/bigquery"
	//   ]
	// }

}

// Pages invokes f for each page of results.
// A non-nil error returned from f will halt the iteration.
// The provided context supersedes any context provided to the Context method.
func (c *ProjectsTransferConfigsRunsTransferLogsListCall) Pages(ctx context.Context, f func(*ListTransferLogsResponse) error) error {
	c.ctx_ = ctx
	defer c.PageToken(c.urlParams_.Get("pageToken")) // reset paging to original point
	for {
		x, err := c.Do()
		if err != nil {
			return err
		}
		if err := f(x); err != nil {
			return err
		}
		if x.NextPageToken == "" {
			return nil
		}
		c.PageToken(x.NextPageToken)
	}
}
