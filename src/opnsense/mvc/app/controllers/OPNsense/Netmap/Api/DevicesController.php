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

use OPNsense\Base\ApiMutableModelControllerBase;
use OPNsense\Core\Config;

/**
 * Names, kinds and notes given to devices in the network map, keyed by MAC address.
 */
class DevicesController extends ApiMutableModelControllerBase
{
    protected static $internalModelName = 'netmap';
    protected static $internalModelClass = 'OPNsense\Netmap\Netmap';

    public function listAction()
    {
        $out = [];
        foreach ($this->getModel()->devices->device->iterateItems() as $uuid => $d) {
            $out[] = [
                'uuid' => $uuid,
                'mac' => strtolower((string)$d->mac),
                'name' => (string)$d->name,
                'kind' => (string)$d->kind,
                'notes' => (string)$d->notes,
                'approved' => (string)$d->approved === '1',
            ];
        }
        return ['devices' => $out];
    }

    /**
     * POST mac, name, kind, notes. Empty name, kind and notes remove the entry.
     */
    public function saveAction()
    {
        if (!$this->request->isPost()) {
            return ['result' => 'failed', 'message' => 'POST required'];
        }
        $mac = strtolower(trim((string)$this->request->getPost('mac')));
        if (!preg_match('/^([0-9a-f]{2}:){5}[0-9a-f]{2}$/', $mac)) {
            return ['result' => 'failed', 'message' => 'invalid MAC address'];
        }
        $values = [];
        foreach (['name', 'kind', 'notes'] as $field) {
            $values[$field] = trim((string)$this->request->getPost($field));
        }
        $mdl = $this->getModel();
        $found = null;
        foreach ($mdl->devices->device->iterateItems() as $uuid => $d) {
            if (strtolower((string)$d->mac) === $mac) {
                $found = $uuid;
                break;
            }
        }
        // an approved device keeps its entry even without name, kind or notes
        $approved = $found !== null && (string)$mdl->getNodeByReference('devices.device.' . $found)->approved === '1';
        if (implode('', $values) === '' && !$approved) {
            if ($found !== null) {
                $mdl->devices->device->del($found);
            }
        } else {
            $node = $found !== null ? $mdl->getNodeByReference('devices.device.' . $found) : $mdl->devices->device->Add();
            $node->setNodes(array_merge(['mac' => $mac], $values));
        }
        $messages = [];
        foreach ($mdl->performValidation() as $msg) {
            $messages[] = $msg->getMessage();
        }
        if (count($messages)) {
            return ['result' => 'failed', 'message' => implode(' ', $messages)];
        }
        $mdl->serializeToConfig();
        Config::getInstance()->save();
        return ['result' => 'saved'];
    }

    /**
     * POST macs: list of MAC addresses to mark as known (approved).
     */
    public function approveAction()
    {
        if (!$this->request->isPost()) {
            return ['result' => 'failed', 'message' => 'POST required'];
        }
        $macs = $this->request->getPost('macs');
        if (!is_array($macs) || count($macs) > 2000) {
            return ['result' => 'failed', 'message' => 'invalid list'];
        }
        $mdl = $this->getModel();
        $byMac = [];
        foreach ($mdl->devices->device->iterateItems() as $uuid => $d) {
            $byMac[strtolower((string)$d->mac)] = $d;
        }
        $count = 0;
        foreach ($macs as $mac) {
            $mac = strtolower(trim((string)$mac));
            if (!preg_match('/^([0-9a-f]{2}:){5}[0-9a-f]{2}$/', $mac)) {
                continue;
            }
            $node = $byMac[$mac] ?? $mdl->devices->device->Add();
            $node->setNodes(['mac' => $mac, 'approved' => '1']);
            $byMac[$mac] = $node;
            $count++;
        }
        $messages = [];
        foreach ($mdl->performValidation() as $msg) {
            $messages[] = $msg->getMessage();
        }
        if (count($messages)) {
            return ['result' => 'failed', 'message' => implode(' ', $messages)];
        }
        $mdl->serializeToConfig();
        Config::getInstance()->save();
        return ['result' => 'saved', 'count' => $count];
    }
}
