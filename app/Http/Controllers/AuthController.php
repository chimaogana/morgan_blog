<?php

namespace App\Http\Controllers;

use Illuminate\Support\Facades\Auth;
use Illuminate\Http\Request;
use Tymon\JWTAuth\Exceptions\JWTException;
use Tymon\JWTAuth\Facades\JWTAuth;
use Validator;
use App\User;


class AuthController extends Controller {

    /**
     * Create a new AuthController instance.
     *
     * @return void
     */
    // public function __construct() {
    //     $this->middleware('auth:api', ['except' => ['login']]);
    // }

    //  public function index(){
    //     try{
    //         return User::select('id','name','email')->get();

    //     }catch(Exception $ex){
    //        return $ex;
    //     }    
    // }

    /**
     * Get a JWT via given credentials.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function login(){
        $credentials = request(['email','password']);
        
            if(!$token = auth()->attempt($credentials)){
                return response()->json(['error'=>"Unauthorized"],401);
            }
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          

        return $this->respondWithToken($token);
    }

    /**
     * Register a User.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function register(Request $request) {
          return User::create([
            'name'=>$request->name,
            'email'=>$request->email,
            'password' => bcrypt($request->password),
          ]);
    }


    /**
     * Log the user out (Invalidate the token).
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function logout() {
        auth()->logout();

        return response()->json(['message' => 'User successfully signed out']);
    }

    /**
     * Refresh a token.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function refresh() {
        return $this->respondWithToken(auth()->refresh());
    }

    /**
     * Get the authenticated User.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function userProfile() {
        return response()->json(auth()->user());
    }

    /**
     * Get the token array structure.
     *
     * @param  string $token
     *
     * @return \Illuminate\Http\JsonResponse
     */
    protected function respondWithToken($token){
        return response()->json([
            'access_token' => $token,
            'token_type' => 'bearer',
            'expires_in' => auth()->factory()->getTTL() * 60,
            
        ]);
    }
    public function payload(){
        return auth()->payload();
    }

    public function update(Request $request)
    {
        $user = User::findOrFail($request->id);
        dd($user);

        // if($user->save()){
        //    return response()->json($user);
        // }
        // $user = auth()->user();
        // if ($request->has('user')) {
        //     $user->update($request->get('user'));
        // }
        
        
        

        // return $this->respondWithToken($token);
    }

   

}