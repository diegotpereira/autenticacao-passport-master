<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Validator;
use Exception;
use GuzzleHttp\Client;
use Auth; 
use Laravel\Passport\Client as OClient; 

class UsuarioController extends Controller
{
    //
	public $sucessoStatus = 200;

	// Usuário Login
	//public function login() {
	//	if (Auth::attempt(['email' => request('email'), 'password' => request('password')])) {
			
	//		return $this->getTokenAndRefreshToken(request('email'), request('password'));
	//	} else {
	//		return response()->json(['error'=> 'Não Autorizado'], 401);
	//	}
	//}
	public function login(Request $request) 
	{
		$data = [
			'email' => $request->email,
			'password' => $request->password
		];

		if (auth()->attempt($data)) {
			$token = auth()->user()->createToken('LaravelAuthApp')->accessToken;

			return response()->json(['token' => $token], 200);
		} else {
			return response()->json(['error' => 'Não Autorizado'], 401);
		}
	}
	// Usuario Registro
	public function registrar(Request $request) 
	{
		$validator = Validator::make($request->all(), [
			'name' => 'required',
			'email' => 'required|email|unique:users',
			'password' => 'required|min:8|confirmed'
		]);
		if ($validator->fails()) {
			return response()->json(['error'=>$validator->errors()], 422);
		}
		$password = $request->password;
		$input = $request->all();
		$input['password'] = bcrypt($input['password']);
		$user = User::create($input);

		return $this->getTokenAndRefreshToken($user->email, $password);
	}
	// Gera o token do portador e atualiza o token
	public function getTokenAndRefreshToken($email, $password) {
		$oClient  = OClient::where('password_client', 1)->first();
		$http = new Client;

		$response = $http->request('POST', env('APP_URL').'/oauth/token', [
			'form_params' => [
				'grant_type' => 'password',
				'client_id' => $oClient->id,
				'client_secret' => $oClient->secret,
				'username' => $email,
				'password' => $password,
				'scope' => '*',
			],
		]);
		$result = json_decode((string) $response->getBody(), true);

		return response()->json($result, $this->sucessoStatus);
	}
}
