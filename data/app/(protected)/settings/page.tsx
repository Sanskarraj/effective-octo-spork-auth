import {auth, signOut} from "@/auth";




const SettingsPage = async() => {

    const session = await auth();


  return (
    <div>
      Settigns page
      <div className="text-8xl">
      {JSON.stringify(session)}
      <form action={async()=>{
        "use server";
        await signOut();

        //here put the refresh code 


      }}>
        <button type="submit" className="border-b-gray-200 border-x-2">signOut</button>
      </form>
      </div>
    </div>
  )
}

export default SettingsPage
