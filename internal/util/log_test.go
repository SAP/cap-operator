/*
SPDX-FileCopyrightText: 2025 SAP SE or an SAP affiliate company and cap-operator contributors
SPDX-License-Identifier: Apache-2.0
*/

package util

import (
	"errors"
	"reflect"
	"testing"

	batchv1 "k8s.io/api/batch/v1"
)

func TestGetLogger(t *testing.T) {
	logger := GetLogger()
	sink := logger.GetSink()
	if sink == nil {
		t.Errorf("Expected zap.Logger sink, got nil")
	}
	if reflect.TypeOf(sink).String() != "*zapr.zapLogger" {
		t.Errorf("Expected *zapr.zapLogger, got %v", reflect.TypeOf(sink))
	}
}

func TestLogging(t *testing.T) {
	jobType := &batchv1.Job{}
	type args struct {
		err    error
		msg    string
		step   string
		entity interface{}
		child  interface{}
		args   []interface{}
	}
	tests := []struct {
		name  string
		error bool
		warn  bool
		args  args
	}{
		{name: "Test LogInfo", error: false, args: args{msg: "LogInfo basic test", step: "LogInfoStep0", entity: "LogInfo", child: "ChildLogInfo", args: []interface{}{"LogInfo", "No missing value"}}},
		{name: "Test LogInfo", error: false, args: args{msg: "LogInfo pointer test", step: "LogInfoStep0", entity: "LogInfo", child: jobType, args: []interface{}{"LogInfo", "No missing value"}}},
		{name: "Test LogError", error: true, args: args{err: errors.New("Test Error"), msg: "LogError basic test", step: "LogErrorStep0", entity: "LogError", child: "ChildLogError", args: []interface{}{"LogError", "No Missing value"}}},
		{name: "Test LogError", error: true, args: args{err: errors.New("Test Error"), msg: "LogError LabelBTPApplicationIdentifierHash skip test", step: "LogErrorStep0", entity: "LogError", child: jobType, args: []interface{}{LabelBTPApplicationIdentifierHash, "some-test-hash", "Missing value"}}},
		{name: "Test LogWarn", warn: true, args: args{err: errors.New("Test Warn"), msg: "LogWarn LabelBTPApplicationIdentifierHash skip test"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.error {
				LogError(tt.args.err, tt.args.msg, tt.args.step, tt.args.entity, tt.args.child, tt.args.args...)
			} else if tt.warn {
				LogWarning(tt.args.err, tt.args.msg)
			} else {
				LogInfo(tt.args.msg, tt.args.step, tt.args.entity, tt.args.child, tt.args.args...)
			}
		})
	}
}
