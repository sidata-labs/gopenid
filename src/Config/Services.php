<?php

namespace SIData\GOpenID\Config;

use CodeIgniter\Config\BaseService;
use SIData\GOpenID\GOpenID;

class Services extends BaseService
{
    public static function GOpenID(bool $getShared = true): GOpenID
    {
        if ($getShared) {
            return static::getSharedInstance('GOpenID');
        }

        return new GOpenID();
    }
}
