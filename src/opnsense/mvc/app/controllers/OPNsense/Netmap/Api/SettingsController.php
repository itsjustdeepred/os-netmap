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

class SettingsController extends ApiMutableModelControllerBase
{
    protected static $internalModelName = 'netmap';
    protected static $internalModelClass = 'OPNsense\Netmap\Netmap';

    /**
     * The options the map page needs (no password).
     */
    public function optionsAction()
    {
        $mdl = $this->getModel();
        $hidden = array_values(array_filter(explode(',', (string)$mdl->general->hidden_networks)));
        return [
            'refresh' => (int)(string)$mdl->general->refresh,
            'new_devices' => (string)$mdl->general->new_devices === '1',
            'firewall_actions' => (string)$mdl->general->firewall_actions === '1',
            'scans' => (string)$mdl->general->scans === '1',
            'hidden_networks' => $hidden,
            'adguard' => (string)$mdl->adguard->enabled === '1' && (string)$mdl->adguard->host !== '' && (string)$mdl->adguard->port !== '',
        ];
    }
}
