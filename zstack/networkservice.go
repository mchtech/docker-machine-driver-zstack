package zstack

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/cnrancher/go-zstack/common"
	"github.com/cnrancher/go-zstack/instance"
	"github.com/pkg/errors"
)

const (
	vipURI             = "/zstack/v1/vips"
	deleteVipURI       = "/zstack/v1/vips/{uuid}"
	deleteInstanceURI  = "/zstack/v1/vm-instances/{uuid}"
	portForwardRuleURI = "/zstack/v1/port-forwarding"
	eipURI             = "/zstack/v1/eips"
)

//CreatePortForwardRuleRequest struct
type CreatePortForwardRuleRequest struct {
	CreatePortForwardRuleContent map[string]string `json:"params,omitempty"`
	Tags                         common.Tags       `json:",inline"`
}

//PortForwardRule struct
type PortForwardRule struct {
	UUID             string `json:"uuid,omitempty"`
	Name             string `json:"name,omitempty"`
	Description      string `json:"description,omitempty"`
	VIPIP            string `json:"vipIp,omitempty"`
	GuestIP          string `json:"guestIp,omitempty"`
	VipUUID          string `json:"vipUuid,omitempty"`
	VipPortStart     uint16 `json:"vipPortStart,omitempty"`
	VipPortEnd       uint16 `json:"vipPortEnd,omitempty"`
	PrivatePortStart uint16 `json:"privatePortStart,omitempty"`
	PrivatePortEnd   uint16 `json:"privatePortEnd,omitempty"`
	VMNicUUID        string `json:"vmNicUuid,omitempty"`
	ProtocolType     string `json:"protocolType,omitempty"`
	State            string `json:"state,omitempty"`
	AllowedCidr      string `json:"allowedCidr,omitempty"`
	CreateDate       string `json:"createDate,omitempty"`
	LastOpDate       string `json:"lastOpDate,omitempty"`
}

//CreatePortForwardRuleResponse struct
type CreatePortForwardRuleResponse struct {
	Error     *common.Error   `json:"error,omitempty"`
	Inventory PortForwardRule `json:"inventory,omitempty"`
}

//QueryPortForwardRulesResponse struct
type QueryPortForwardRulesResponse struct {
	Error       *common.Error     `json:"error,omitempty"`
	Inventories []PortForwardRule `json:"inventories,omitempty"`
}

//CreateVipRequest struct
type CreateVipRequest struct {
	CreateVipContent map[string]string `json:"params,omitempty"`
	Tags             common.Tags       `json:",inline"`
}

//VipRule struct
type VipRule struct {
	UUID              string   `json:"uuid,omitempty"`
	Name              string   `json:"name,omitempty"`
	Description       string   `json:"description,omitempty"`
	L3NetworkUUID     string   `json:"l3NetworkUuid,omitempty"`
	IP                string   `json:"ip,omitempty"`
	State             string   `json:"state,omitempty"`
	Gateway           string   `json:"gateway,omitempty"`
	Netmask           string   `json:"netmask,omitempty"`
	ServiceProvider   string   `json:"serviceProvider,omitempty"`
	PeerL3NetworkUUID []string `json:"peerL3NetworkUuid,omitempty"`
	UseFor            string   `json:"useFor,omitempty"`
	CreateDate        string   `json:"createDate,omitempty"`
	LastOpDate        string   `json:"lastOpDate,omitempty"`
}

//CreateVipResponse struct
type CreateVipResponse struct {
	Error     *common.Error `json:"error,omitempty"`
	Inventory VipRule       `json:"inventory,omitempty"`
}

//VipResponses struct
type VipResponses struct {
	Error       *common.Error `json:"error,omitempty"`
	Inventories []VipRule     `json:"inventories,omitempty"`
}

//CreateEipRequest struct
type CreateEipRequest struct {
	CreateEipContent map[string]string `json:"params,omitempty"`
	Tags             common.Tags       `json:",inline"`
}

//CreateEipResponse struct
type CreateEipResponse struct {
	Error     *common.Error `json:"error,omitempty"`
	Inventory struct {
		UUID        string `json:"uuid,omitempty"`
		Name        string `json:"name,omitempty"`
		Description string `json:"description,omitempty"`
		VMNicUUID   string `json:"vmNicUuid,omitempty"`
		VipUUID     string `json:"vipUuid,omitempty"`
		CreateDate  string `json:"createDate,omitempty"`
		LastOpDate  string `json:"lastOpDate,omitempty"`
		State       string `json:"state,omitempty"`
		VipIP       string `json:"vipIp,omitempty"`
		GuestIP     string `json:"guestIp,omitempty"`
	} `json:"inventory,omitempty"`
}

//CreateEip will map created public vip to vm private ip
func (d *Driver) CreateEip(vipuuid string, vmnicuuid string) error {
	d.initClients()
	eip := CreateEipRequest{
		CreateEipContent: map[string]string{
			"name":      "eip-for-rancher-" + d.InstanceUUID,
			"vipUuid":   vipuuid,
			"vmNicUuid": vmnicuuid,
		},
		Tags: common.Tags{
			SystemTags: []string{},
			UserTags:   []string{},
		},
	}
	requestBody, _ := json.Marshal(eip)
	resp, err := d.getInstanceClient().CreateRequestWithURI(http.MethodPost, eipURI, requestBody)

	if err != nil {
		return err
	}

	async, err := common.GetAsyncResponse(d.client, resp)
	responseStruct := CreateEipResponse{}

	if err = async.QueryRealResponse(&responseStruct, 60*time.Second); err != nil {
		return errors.Wrap(err, "Get error when query response for zstack create EIP job.")
	}
	if responseStruct.Error != nil {
		return errors.Wrap(responseStruct.Error.WrapError(), "Get error when create zstack EIP.")
	}
	return nil
}

//CreateVip will create a public vip from provided public L3 network pool
func (d *Driver) CreateVip() (string, string, error) {
	d.initClients()
	vip := CreateVipRequest{
		CreateVipContent: map[string]string{
			"name":          "vip-for-rancher-" + d.InstanceUUID,
			"l3NetworkUuid": d.PublicL3NetworkUUID,
		},
		Tags: common.Tags{
			SystemTags: []string{},
			UserTags:   []string{},
		},
	}
	requestBody, _ := json.Marshal(vip)

	resp, err := d.getInstanceClient().CreateRequestWithURI(http.MethodPost, vipURI, requestBody)

	if err != nil {
		return "", "", err
	}

	async, err := common.GetAsyncResponse(d.client, resp)
	responseStruct := CreateVipResponse{}

	if err = async.QueryRealResponse(&responseStruct, 60*time.Second); err != nil {
		return "", "", errors.Wrap(err, "Get error when query response for zstack create VIP job.")
	}
	if responseStruct.Error != nil {
		return "", "", errors.Wrap(responseStruct.Error.WrapError(), "Get error when delete zstack VIP.")
	}
	return responseStruct.Inventory.IP, responseStruct.Inventory.UUID, nil
}

//DeleteVip will delete public vip and related EIP and/or Portforwarding rules
func (d *Driver) DeleteVip() error {
	d.initClients()
	// _, publicipv4uuid, err := d.QueryVipIPUUID()
	// if err != nil {
	// 	return err
	// }

	if d.PublicIPv4UUID == "" {
		return errors.New("PublicIPv4UUID is empty")
	}

	realURI := strings.Replace(deleteVipURI, "{uuid}", d.PublicIPv4UUID, -1)
	resp, err := d.getInstanceClient().CreateRequestWithURI(http.MethodDelete, realURI, nil)
	if err != nil {
		return err
	}

	async, err := common.GetAsyncResponse(d.client, resp)
	responseStruct := CreateVipResponse{}

	if err = async.QueryRealResponse(&responseStruct, 60*time.Second); err != nil {
		return errors.Wrap(err, "Get error when query response for zstack delete vip job.")
	}
	if responseStruct.Error != nil {
		return errors.Wrap(responseStruct.Error.WrapError(), "Get error when delete zstack vip.")
	}
	return nil
}

//CreatePortForwardRule will create a tcp or udp port forward rule from port 1 to 65535
func (d *Driver) CreatePortForwardRule(vipuuid string, vmnicuuid string, proto string) error {
	d.initClients()
	portforward := CreatePortForwardRuleRequest{
		CreatePortForwardRuleContent: map[string]string{
			"vipUuid":          vipuuid,
			"vipPortStart":     "1",
			"vipPortEnd":       "65535",
			"privatePortStart": "1",
			"privatePortEnd":   "65535",
			"protocolType":     proto,
			"vmNicUuid":        vmnicuuid,
			"name":             "pf-for-rancher-" + proto + "-" + d.InstanceUUID,
		},
		Tags: common.Tags{
			SystemTags: []string{},
			UserTags:   []string{},
		},
	}
	requestBody, _ := json.Marshal(portforward)
	resp, err := d.getInstanceClient().CreateRequestWithURI(http.MethodPost, portForwardRuleURI, requestBody)
	if err != nil {
		return err
	}
	responseStruct := CreatePortForwardRuleResponse{}
	async, err := common.GetAsyncResponse(d.client, resp)

	if err = async.QueryRealResponse(&responseStruct, 60*time.Second); err != nil {
		return errors.Wrap(err, "Get error when query response for zstack create portforward rules.")
	}
	if responseStruct.Error != nil {
		return errors.Wrap(responseStruct.Error.WrapError(), "Get error when create portforward rules.")
	}
	return nil
}

func (d *Driver) findDefaultNetworkVMNic(vmnics []*instance.VMNic) *instance.VMNic {
	// L3NetworkNames Param is not a optional param.
	defaultL3UUID := d.getNetworks()[0]
	for _, nic := range vmnics {
		if nic.L3NetworkUUID == defaultL3UUID {
			return nic
		}
	}
	return nil
}

//QueryVipIPUUID will return vip and its uuid of current instance
func (d *Driver) QueryVipIPUUID() (string, string, error) {
	d.initClients()
	inventory, err := d.getInstanceClient().QueryInstance(d.InstanceUUID)
	if err != nil {
		return "", "", err
	}
	if len(inventory.VMNics) == 0 {
		return "", "", fmt.Errorf("Nics not found")
	}

	GuestIP := d.findDefaultNetworkVMNic(inventory.VMNics).IP
	var realURI string

	if strings.ToLower(d.PublicL3NetworkMode) == "portforward" {
		realURI = fmt.Sprintf("%s?q=portForwarding.guestIp=%s", vipURI, GuestIP)
	} else if strings.ToLower(d.PublicL3NetworkMode) == "eip" {
		realURI = fmt.Sprintf("%s?q=eip.guestIp=%s", vipURI, GuestIP)
	} else {
		return "", "", fmt.Errorf("Unsupported network mode")
	}
	resp, err := d.getInstanceClient().CreateRequestWithURI(http.MethodGet, realURI, nil)
	if err != nil {
		return "", "", err
	}
	responseBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", "", err
	}
	responseStruct := VipResponses{}
	if err = json.Unmarshal(responseBody, &responseStruct); err != nil {
		logrus.Warnf("Unmarshaling response when Querying pf rules. Error: %s", err.Error())
	}
	if resp.StatusCode != 200 {
		if responseStruct.Error != nil {
			return "", "", responseStruct.Error.WrapError()
		}
		return "", "", fmt.Errorf("status code %d,Error massage %s", resp.StatusCode, string(responseBody))
	}
	if len(responseStruct.Inventories) > 0 {
		return responseStruct.Inventories[0].IP, responseStruct.Inventories[0].UUID, nil
	}
	return "", "", fmt.Errorf("Not any portforward rules")
}
