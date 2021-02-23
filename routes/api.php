<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\AuthController;
use Illuminate\Support\Facades\Auth;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| is assigned the "api" middleware group. Enjoy building your API!
|
*/

Route::middleware('auth:api')->group(function () {
    Route::delete('/auth/delete', [AuthController::class, 'delete']);
    Route::put('/auth/edit', [AuthController::class, 'update']);
    Route::get('/auth/logout', [AuthController::class, 'logout']);
    Route::get('/auth/user', function(){
        return response()->json([
        'user' => Auth::user()
        ]);
    });
});

Route::get('/401', [AuthController::class, 'unauthorized'])->name('login');
Route::post('/auth/login', [AuthController::class, 'login']);
Route::post('/auth/register', [AuthController::class, 'create']);