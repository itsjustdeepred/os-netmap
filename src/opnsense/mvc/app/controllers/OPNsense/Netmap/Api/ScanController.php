<?php

/*
 * Copyright (C) 2026 os-netmap contributors
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

namespace OPNsense\Netmap\Api;

use OPNsense\Base\ApiControllerBase;
use OPNsense\Core\Backend;

/**
 * Port scan of one device with nmap. The backend only scans addresses on
 * networks attached to the firewall (not the uplink, not VPNs).
 */
class ScanController extends ApiControllerBase
{
    private function valid($ip)
    {
        return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false;
    }

    private function run($action, $params)
    {
        if (method_exists($this, 'sessionClose')) {
            $this->sessionClose();
        }
        $response = trim((new Backend())->configdpRun('netmap scan ' . $action, $params));
        return json_decode($response, true) ?? ['status' => 'error', 'message' => $response];
    }

    private function validMac($mac)
    {
        return preg_match('/^([0-9a-f]{2}:){5}[0-9a-f]{2}$/', $mac) === 1;
    }

    /**
     * Results belong to the device (MAC address); the scan targets its current address.
     */
    public function startAction($mac = '', $ip = '', $profile = 'quick')
    {
        if (!$this->request->isPost()) {
            return ['status' => 'error', 'message' => 'POST required'];
        }
        // the page sends aa-bb-cc-dd-ee-ff: colons do not survive in a URL path
        $mac = strtolower(str_replace('-', ':', $mac));
        if (!$this->validMac($mac) || !$this->valid($ip) || !in_array($profile, ['quick', 'full'], true)) {
            return ['status' => 'error', 'message' => 'invalid request'];
        }
        return $this->run('start', [$mac, $ip, $profile]);
    }

    public function statusAction($mac = '')
    {
        $mac = strtolower(str_replace('-', ':', $mac));
        if (!$this->validMac($mac)) {
            return ['status' => 'error', 'message' => 'invalid MAC address'];
        }
        return $this->run('status', [$mac]);
    }

    public function listAction()
    {
        return $this->run('list', []);
    }
}
