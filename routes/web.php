<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\AuthController;


Route::get('/login', function () {
  return response()->json(['error' => 'Unauthorized'], 401);
})->name('login');
