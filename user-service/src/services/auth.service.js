import { ConflictError, BadRequestError, ForbiddenError } from '../utils/error.js';
import { generateAndStoreOtp, verifyOtp } from '../utils/otp.js';
import { sendOtpEmail, verifyOtpEmail } from '../utils/email.js';
import { generateAccessToken, generateRefreshToken, verifyRefreshToken } from '../utils/auth.js';
import bcrypt from 'bcrypt';
import prisma from '../config/prisma.js';
import { redis } from '../config/redis.js';
import { config } from '../config/index.js';
import logger from '../config/logger.js';
import jwt from 'jsonwebtoken';
import otpGenerator from 'otp-generator';

const { generate } = otpGenerator;


const sendOTP = async(firstName, lastName, email, password) =>{
     const existingUser = await prisma.user.findUnique({
          where: {email}
     })

     if(existingUser){
          throw new ConflictError("user already exists");
     }
     const hashedPassword = await bcrypt.hash(password, 12);
     const meta = {firstName, lastName, email, hashedPassword};
     const {otp, otpSessionId} = await generateAndStoreOtp(meta);
     await sendOtpEmail(email, otp);
     return {otpSessionId}
}

const verifyOTP = async(otp, otpSessionId) =>{
     const meta = await verifyOtp(otp, otpSessionId);
     if(meta === null){
          throw new BadRequestError("Invalid or expired OTP", "OTP_INVALID");
     }
     const user = await prisma.user.create({
          data: {
               firstName: meta.firstName,
               lastName: meta.lastName,
               email: meta.email,
               password: meta.hashedPassword,
               emailVerified: true
          }
     })

     await verifyOtpEmail(meta);
     return user;

}

const login = async(email, password, deviceId) =>{
     const existingUser = await prisma.user.findUnique({
          where: {email}
     })
     if(!existingUser){
          throw new BadRequestError("Email not found")
     }
     const doesPasswordMatch = await bcrypt.compare(password, existingUser.password);
     if(!doesPasswordMatch){
          throw new BadRequestError("Incorrect Password");
     }
     const accessToken = generateAccessToken(existingUser.id);
     const refreshToken = generateRefreshToken(existingUser.id);
     const {jti} = jwt.decode(refreshToken);
     await redis.set(`refresh:${existingUser.id}:${deviceId}`, jti, 'EX', config.REFRESH_TOKEN_EXP_SEC);
     const {password: _password, ...safeUser} = existingUser;
     await redis.set(`user:${existingUser.id}`, JSON.stringify(safeUser), 'EX', config.REDIS_USER_TTL);
     return {accessToken, refreshToken, loggedInUser: safeUser};
}


const rotateRefreshToken = async(refreshToken, deviceId) =>{
     const payload = verifyRefreshToken(refreshToken);
     const {id: userId, jti} = payload;
     const storedJti = await redis.get(`refresh:${userId}:${deviceId}`);
     if(!storedJti){
          throw new ForbiddenError("Session Expired", "Login AGAIN")
     }
     if(storedJti !== jti){
          await redis.del(`refresh:${userId}:${deviceId}`);
          throw new ForbiddenError("Refresh token reused", "LOGIN AGAIN")
     }
     const newAccessToken = generateAccessToken(payload.id);
     const newRefreshToken = generateRefreshToken(payload.id);
     const {jti: newJti} = jwt.decode(newRefreshToken);
     await redis.set(`refresh:${payload.id}:${deviceId}`, newJti, 'EX', config.REFRESH_TOKEN_EXP_SEC);
     return {newAccessToken, newRefreshToken};
}
export { sendOTP, verifyOTP, login, rotateRefreshToken };
