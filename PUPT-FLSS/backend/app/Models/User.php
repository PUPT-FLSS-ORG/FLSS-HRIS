<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;
use Illuminate\Support\Facades\Hash;
use Laravel\Sanctum\HasApiTokens;

class User extends Authenticatable
{
    use HasApiTokens, HasFactory, Notifiable;
    
    protected $fillable = [
        'first_name',
        'middle_name',
        'last_name',
        'suffix_name',
        'code',
        'email',
        'password',
        'role',
        'status',
    ];

    /**
     * Default accessor to get the full name.
     */
    public function getNameAttribute()
    {
        $fullName = $this->first_name;
        if ($this->middle_name) {
            $fullName .= ' ' . $this->middle_name;
        }
        $fullName .= ' ' . $this->last_name;
        if ($this->suffix_name) {
            $fullName .= ' ' . $this->suffix_name;
        }
        return $fullName;
    }

    /**
     * New accessor to get the formatted name 
     * Format: last_name, first_name middle_name suffix_name
     */
    public function getFormattedNameAttribute()
    {
        $formattedName = $this->last_name;
        $formattedName .= ', ' . $this->first_name;
        
        if ($this->middle_name) {
            $formattedName .= ' ' . $this->middle_name;
        }
        
        if ($this->suffix_name) {
            $formattedName .= ' ' . $this->suffix_name;
        }
        
        return $formattedName;
    }

    /**
     * Hash the password before saving to the database.
     */
    public function setPasswordAttribute($value)
    {
        if (!Hash::needsRehash($value)) {
            $value = Hash::make($value);
        }
        $this->attributes['password'] = $value;
    }

    public function faculty()
    {
        return $this->hasOne(Faculty::class, 'user_id');
    }

}