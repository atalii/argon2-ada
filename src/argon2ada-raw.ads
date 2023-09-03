--  This Source Code Form is subject to the terms of the Mozilla Public License,
--  v. 2.0. If a copy of the MPL was not distributed with this file, You can
--  obtain one at https://mozilla.org/MPL/2.0/.

with Interfaces.C.Strings;
use Interfaces.C.Strings;

with Argon2Ada;

package Argon2Ada.Raw is
   --  Contains very raw bindings to the underlying lib.

   type Context is record
      Output : System.Address;
      Output_Len : Argon2Ada.Uint32;

      Pwd : System.Address;
      Pwd_Len : Argon2Ada.Uint32;

      Salt : System.Address;
      Salt_Len : Argon2Ada.Uint32;

      Secret : System.Address;
      Secret_Len : Argon2Ada.Uint32;

      AD : System.Address;
      AD_Len : Argon2Ada.Uint32;

      Time_Cost : Argon2Ada.Uint32;
      Mem_Cost : Argon2Ada.Uint32;
      Lanes : Argon2Ada.Uint32;
      Threads : Argon2Ada.Uint32;

      Version : Argon2Ada.Uint32;

      Allocate_Cbk : System.Address;
      Deallocate_Cbk : System.Address;

      Flags : Argon2Ada.Uint32;
   end record;

   function Type_To_String (Alg : Integer; Uppercase : Integer) return chars_ptr;

   function Ctx (Context : System.Address; Argon2_Type : Integer) return Integer;

   pragma Import
      (Convention => C, Entity => Type_To_String, External_Name => "argon2_type2string");

   pragma Import
      (Convention => C, Entity => Ctx, External_Name => "argon2_ctx");
end Argon2Ada.Raw;
