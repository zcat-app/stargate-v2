// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.manager;

interface ProxyControl {
    record Unit(String observation, String loadState, String activeState, String subState,
                Long pid, String invocationId, String result, Integer exitStatus, String code) {}
    record Command(boolean success, String code) {}
    Unit sample();
    Command action(String action);
}
