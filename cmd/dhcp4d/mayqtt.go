package main

import (
	"fmt"
	"io/ioutil"
	"path"
	"strings"

	mqtt "github.com/eclipse/paho.mqtt.golang"
)

type PublishRequest struct {
	Topic    string
	Qos      byte
	Retained bool
	Payload  interface{}
}

func publisherLoop(requests <-chan PublishRequest) error {
	configFn := path.Join(*perm, "/dhcp4d/mqtt-broker.txt")
	b, err := ioutil.ReadFile(configFn)
	if err != nil {
		// discard requests:
		for range requests {
		}
		return nil
	}
	var (
		broker   string
		username string
		password string
	)
	cfg := strings.Split(string(b), "\n")

	// e.g. tcp://10.0.0.54:1883, which is a static DHCP lease for the dr.lan
	// Raspberry Pi, which is running an MQTT broker in my network.
	broker = strings.TrimSpace(cfg[0])
	if len(cfg) > 1 {
		username = cfg[1]
	}
	if len(cfg) > 2 {
		password = cfg[2]
	}
	log.Printf("Connecting to MQTT broker %q (configured in %s)", broker, configFn)
	opts := mqtt.NewClientOptions().AddBroker(broker)
	opts.SetUsername(username)
	opts.SetPassword(password)
	opts.SetClientID("dhcp4d")
	opts.SetConnectRetry(true)
	mqttClient := mqtt.NewClient(opts)
	if token := mqttClient.Connect(); token.Wait() && token.Error() != nil {
		return fmt.Errorf("MQTT connection failed: %v", token.Error())
	}

	for r := range requests {
		// discard Token, MQTT publishing is best-effort
		_ = mqttClient.Publish(r.Topic, r.Qos, r.Retained, r.Payload)
	}
	return nil
}

func MQTT() chan<- PublishRequest {
	result := make(chan PublishRequest)
	go func() {
		if err := publisherLoop(result); err != nil {
			log.Print(err)
		}
	}()
	return result
}
