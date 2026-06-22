<?php

namespace App\Authorization\Gates;

class GateRegistrar
{
    public static function register(): void
    {
        foreach ([
            \App\Authorization\Gates\Dashboard\EmployeeGates::class,
        ] as $class) {
            $class::register();
        }
    }
}
