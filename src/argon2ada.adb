--  This Source Code Form is subject to the terms of the Mozilla Public License,
--  v. 2.0. If a copy of the MPL was not distributed with this file, You can
--  obtain one at https://mozilla.org/MPL/2.0/.

with System;
use System;

with System.Storage_Elements;

with Interfaces.C.Strings;
use Interfaces.C.Strings;

with Argon2Ada.Raw;

package body Argon2Ada is

   function Type_To_String (Alg : Alg_Type) return String
   is
      X : constant Integer := Alg_Type'Enum_Rep (Alg);
      Ptr : constant chars_ptr := Argon2Ada.Raw.Type_To_String (X, 1);
   begin
      if Ptr = Null_Ptr then
         raise Unreachable with "argon2_type2string: got NULL";
         --  Due to the type system restricting the acceptable values for
         --  Alg_Type, reaching this code path indicates a serious issue.
      end if;

      return Value (Ptr);
   end Type_To_String;

   function Buffer_To_String_Hex (Buffer : Byte_Buf) return String
   is

      type Digit is range 0 .. 15;

      function To_Digit (H : Digit) return Character
      is
         Off : Integer;
      begin
         if H < 10 then
            Off := 48;
         else
            Off := 97 - 10;
         end if;

         return Character'Val (Integer (H) + Off);
      end To_Digit;

      N : constant Integer := Buffer'Length * 2;
      R : String (1 .. N);

      B : Uint8;
      Most_Significant : Digit;
      Least_Significant : Digit;

   begin
      for I in 1 .. Buffer'Length loop
         B := Buffer (Buffer'First - 1 + I);
         Most_Significant := Digit (B / 16);
         Least_Significant := Digit (B mod 16);

         R (I * 2 - 1) := To_Digit (Most_Significant);
         R (I * 2) := To_Digit (Least_Significant);
      end loop;
      return R;
   end Buffer_To_String_Hex;

   package body Hasher is

      function Fill_Pass_Buf (Pass : String) return Pass_Buf
      is
         -- TODO: make sure that String <= Pass_Len
         R : Pass_Buf;
      begin
         for I in 1 .. Pass'Length loop
            R (I) := Uint8 (Character'Pos (Pass (I)));
         end loop;

         for I in (Pass'Length + 1) .. Integer (Pass_Len) loop
            R (I) := 0;
         end loop;

         return R;
      end Fill_Pass_Buf;

      function Hash
         (C : Config;
         Pass : in out Pass_Buf;
         Salt : in out Salt_Buf;
         Secret : Secret_Buf := (others => 0);
         AD : AD_Buf := (others => 0)) return Result
      is
         Buf : Result_Buf;

         Raw_Ctx : constant Raw.Context :=
               (Output => Buf'Address, Output_Len => Output_Len,
               Pwd => Pass'Address, Pwd_Len => Pass_Len,
               Salt => Salt'Address, Salt_Len => Uint32 (Salt_Len),
               Secret => Secret'Address, Secret_Len => Secret_Len,
               AD => AD'Address, AD_Len => Associated_Data_Len,
               Time_Cost => C.Time_Cost, Mem_Cost => C.Mem_Cost,
               Lanes => C.Lanes, Threads => C.Threads,
               Version => C.Version,
               Allocate_Cbk => System.Null_Address,
               Deallocate_Cbk => System.Null_Address,
               Flags => Uint32 (Flag'Enum_Rep (C.Flags)));

         T : constant Integer := Alg_Type'Enum_Rep (C.Alg);
         R : constant Integer := Argon2Ada.Raw.Ctx (Raw_Ctx'Address, T);
         E : constant Error := R;

         Ret : Result;

      begin

         if E /= 0 then
            Ret := (Ok => False, Err => E);
         else
            Ret := (Ok => True, Data => Buf);
         end if;

         return Ret;

      exception

         when Constraint_Error =>
            raise Unreachable with "Unknown error code.";
      end Hash;

   end Hasher;

end Argon2Ada;
