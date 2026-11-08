<?php

if (!function_exists('GOpenID')) {
    function GOpenID(): \SIData\GOpenID\GOpenID {
        return service('GOpenID');
    }
}
