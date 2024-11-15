﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;

namespace Nuevapruebagit.Controllers
{
    public class HomeController : Controller
    {
        public ActionResult Index()
        {
            Models.Encriptador encriptador = new Models.Encriptador();
            string datos=encriptador.Encriptar("Hola mundo");
            string datosnew=encriptador.Desencriptar(datos);
            string datos2 = encriptador.Encriptar("Hola mundo26516156");
            string datosnew2 = encriptador.Desencriptar(datos);
            string datos3 = encriptador.Encriptar("Hola mundo26516156");
            string datosnew3 = encriptador.Desencriptar(datos);
            return View();
        }

        public ActionResult About()
        {
            ViewBag.Message = "Your application description page.";

            return View();
        }

        public ActionResult Contact()
        {
            ViewBag.Message = "Your contact page.";

            return View();
        }
    }
}