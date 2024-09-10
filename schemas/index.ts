import * as z from "zod";


export const LoginSchema =  z.object({
    email:z.string().email({
        message:"Email is required"
    }),
    password: z.string().min(1,{
        message:"Password is required"
    })
})




export const Registerschema =  z.object({
    email:z.string().email({
        message:"Email is required"
    }),
    password: z.string().min(1,{
        message:"Password is required"
    }),
    username: z.string().min(1,{
        message:"username is required"
    }),
    country: z.string().min(1,{
        message:"country is required"
    }),
    key: z.string()
})
