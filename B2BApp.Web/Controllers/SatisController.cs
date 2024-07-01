﻿using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json.Linq;
using System.IdentityModel.Tokens.Jwt;

namespace B2BApp.Web.Controllers
{
    public class SatisController : Controller
    {
        // GET: SatisController
        public ActionResult Index()
        {
            // JWT'yi çözme
            if (Request.Cookies["jwt"] == null) return RedirectToAction("login", "Account");
            ViewBag.JwtCookie = Request.Cookies["jwt"];
            return View();
        }

           // GET: SatisController
        public ActionResult SatisRapor()
        {
            // JWT'yi çözme
            if (Request.Cookies["jwt"] == null) return RedirectToAction("login", "Account");
            var handler = new JwtSecurityTokenHandler();
            var jsonToken = handler.ReadToken(Request.Cookies["jwt"]) as JwtSecurityToken;

            // Claims (iddialar) JSON olarak okuma
            var claimsJson = new JObject();
            foreach (var claim in jsonToken.Claims)
            {
                claimsJson.Add(claim.Type, claim.Value);
            }
            ViewBag.FirmaId = claimsJson["role"].ToString();
            ViewBag.JwtCookie = Request.Cookies["jwt"];


            return View();
        }

       



       
    }
}
