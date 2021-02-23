<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Facades\Auth;

class AuthController extends Controller
{
    public function create(Request $request) {
        $rules = [ 
            'name' => ['required'],
            'email' => ['required', 'unique:users,email', 'email'],
            'password' => ['required'],
            'confirm_password' => ['required', 'same:password']
        ];

        $validator = Validator::make($request->all(), $rules);

        if($validator->fails()) {
            return response()->json([
                'error' => $validator->errors()->first()
            ], Response::HTTP_OK);
        }

        $name = $request->input('name');
        $email = $request->input('email');
        $password = $request->input('password');

        $newUser = new User();
        $newUser->name = $name;
        $newUser->email = $email;
        $newUser->password = password_hash($password, PASSWORD_DEFAULT);

        $newUser->save();

        $token = Auth::attempt(['email' => $email, 'password' => $password]);

        return $this->respondWithToken($token);
    }

    public function login(Request $request){

        $rules = [ 
            'email' => ['required', 'email'],
            'password' => ['required']
        ];

        $validator = Validator::make($request->all(), $rules);

        if($validator->fails()) {
            return response()->json([
                'error' => $validator->errors()->first()
            ]);
        }

        $creds = $request->only('email', 'password');

        if($token = Auth::attempt($creds)){
            return $this->respondWithToken($token);
        }else {
            return response()->json([
                'error' => "E-mail e/ou senha incorretos."
            ]);
        }
        
    }

    public function update(Request $request) {
        
        $rules = [ 
            'name' => ['required'],
            'confirm_password' => ['required_with:password', 'same:password']
        ];
        $validator = Validator::make($request->all(), $rules);
        if($validator->fails()) {
            return response()->json([
                'error' => $validator->errors()->first()
            ]);
        }
        $user = $request->user();
        $user->name = $request->name;
        if($request->password) {
            $user->password = $request->password;
        } else { 
            $user->password = $user->password;
        }
        $user->save();

        return response()->json([
            'success' => 'Usuário atualizado com sucesso.'
        ]);
        
    }

    public function delete(Request $request) {
        $user = $request->user();
        $user->delete();
        
        return response()->json([
            'success' => 'usuario deletado com sucesso'
        ]);
    }

    public function unauthorized() {
        return response()->json([
            'erro' => 'deu ruim'
        ]);
    }

    public function logout(Request $request) {
        Auth()->logout();
        return response()->json([
            'success' => 'Deslogado com sucesso.'
        ]);
    }

    protected function respondWithToken($token)
    {
        return response()->json([
            'token' => $token,
            'token_type' => 'bearer',
            'error' => ''
        ]);
    }
}
